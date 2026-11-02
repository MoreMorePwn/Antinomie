// SPDX-License-Identifier: GPL-3.0-only
//! Native retained-evidence workspace; all acquisition remains outside rendering.
mod capa_matrix;
pub(crate) mod chosen;
pub(crate) mod content;
mod export;
mod limits;
mod tabs;
mod unpacking;

use self::export::export_controls;
use self::tabs::{FileInfo, Tab};
use super::{
    records::{self, Column, Structure},
    row_menu::{self, RowCommand, RowWindows},
    section_title, ReportAction,
};
use crate::widgets::fit_table::{Col as TableColumn, FitBuilder};
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisExportFormat, AnalysisKind, AnalysisListingPage,
    AnalysisReport, AnalysisSection, AnalysisSpecimenPage, AnalysisState,
};
use eframe::egui;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct WorkspaceState {
    report_id: Option<String>,
    kind: Option<AnalysisKind>,
    structure: Structure,
    views: BTreeMap<String, ViewState>,
    active_view: Option<String>,
    record_id: String,
    record_name: String,
    record_path: String,
    record_tags: Vec<String>,
    identities: Vec<(&'static str, crate::query::RowValue)>,
    tab: Tab,
    file_info: FileInfo,
    symbols: Structure,
    content: content::ContentState,
    capa: capa_matrix::CapaState,
    rows: RowWindows,
    /// The regex matches pane of the Regex matches tab, over the report's strings.
    regex: crate::regex_matches::RegexWindow,
    /// The layer the Unpacking tab shows.
    unpack_layer: usize,
    /// The report whose scan the pane has asked for, so it asks once.
    regex_asked: String,
    /// The pane wants its scan started; the app takes this once.
    regex_wanted: bool,
    /// The row last handed to the Details panel, so it is handed over once.
    published: Option<AnalysisEntry>,
    /// A filter that finds the row a note names, applied to its section the
    /// next time that section is drawn.
    row_query: Option<(AnalysisKind, String)>,
}

/// A view inside a category pane that a link from another window names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubTab {
    Sections,
    Symbols,
}

impl WorkspaceState {
    /// Show the `sub` view of a category pane, as if it had been picked in the
    /// pane's own filter.
    pub(crate) fn show_sub_tab(&mut self, sub: SubTab) {
        self.structure = match sub {
            SubTab::Sections => Structure::Sections,
            SubTab::Symbols => Structure::Symbols,
        };
    }

    /// Hand the row selected in the shown category to the Details panel when
    /// it differs from the one handed over last.
    fn publish(
        &mut self,
        ctx: &egui::Context,
        report: &AnalysisReport,
        forced: Option<AnalysisKind>,
    ) {
        if forced.is_none() && self.tab == Tab::Content {
            return;
        }
        let Some(kind) = forced.or(self.kind) else {
            return;
        };
        let Some(entry) = tabs::selected_row(report, self, forced) else {
            return;
        };
        if self.published.as_ref() == Some(entry) {
            return;
        }
        let chosen = chosen::ChosenRow {
            entry: entry.clone(),
            specimen_len: report.specimen_len,
            category: section_title(kind),
        };
        self.published = Some(chosen.entry.clone());
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(chosen::CHOSEN_ROW), chosen));
    }

    /// The report whose regex scan the Regex matches tab asked for, once.
    pub(crate) fn take_regex_request(&mut self) -> Option<String> {
        std::mem::take(&mut self.regex_wanted)
            .then(|| self.report_id.clone())
            .flatten()
    }

    /// Start the regex scan for the report kept in `directory`.
    pub(crate) fn scan_regex(
        &mut self,
        report_id: &str,
        title: String,
        directory: std::path::PathBuf,
    ) {
        let id = report_id.to_owned();
        self.regex.open_for(
            report_id,
            title,
            std::sync::Arc::new(move |rules, cancel| {
                antinomie_monitor_core::strings_regex::scan_report(&directory, &id, rules, cancel)
            }),
        );
    }

    pub(crate) fn set_record(&mut self, id: &str, name: &str, path: &str, tags: Vec<String>) {
        self.record_id = id.to_owned();
        self.record_name = name.to_owned();
        self.record_path = path.to_owned();
        self.record_tags = tags;
    }

    pub(crate) fn set_identities(
        &mut self,
        identities: Vec<(&'static str, crate::query::RowValue)>,
    ) {
        self.identities = identities;
    }

    pub(crate) fn record_context(
        &self,
        report: &AnalysisReport,
    ) -> Vec<(&'static str, crate::query::RowValue)> {
        use crate::query::RowValue as V;
        let mut row = crate::query::label_row(
            &report.id,
            &self.record_name,
            &report.source_path,
            &self.record_tags,
        );
        row.extend([
            ("entry.kind", V::Text("analysis".into())),
            ("entry.state", V::Text(format!("{:?}", report.state))),
            (
                "entry.complete",
                V::Bool(report.state == AnalysisState::Complete),
            ),
            (
                "entry.size",
                report
                    .specimen_len
                    .map_or(V::Missing, |size| V::Number(size.into())),
            ),
            ("analysis.id", V::Text(report.id.clone())),
            ("analysis.state", V::Text(format!("{:?}", report.state))),
            ("analysis.source", V::Text(report.source_path.clone())),
            ("analysis.path", V::Text(report.source_path.clone())),
            (
                "analysis.sha256",
                report
                    .specimen_sha256
                    .as_ref()
                    .map_or(V::Missing, |hash| V::Text(hash.clone())),
            ),
            (
                "analysis.tool",
                V::List(
                    report
                        .sections
                        .iter()
                        .flat_map(|section| section.tools.iter().cloned())
                        .collect(),
                ),
            ),
            (
                "analysis.has_run",
                V::Bool(self.identities.iter().any(|(key, _)| *key == "run.id")),
            ),
        ]);
        row.extend(self.identities.clone());
        if let Some((_, value)) = self.identities.iter().find(|(key, _)| *key == "run.id") {
            row.push(("analysis.run_id", value.clone()));
        }
        row
    }

    /// The program run this report belongs to, when it has one.
    pub(crate) fn linked_run(&self) -> Option<&str> {
        self.identities.iter().find_map(|(key, value)| match value {
            crate::query::RowValue::Text(id) if *key == "run.id" => Some(id.as_str()),
            _ => None,
        })
    }

    pub(crate) fn record_context_for(
        &self,
        report: &AnalysisReport,
        kind: AnalysisKind,
    ) -> Vec<(&'static str, crate::query::RowValue)> {
        let mut row = self.record_context(report);
        row.retain(|(key, _)| *key != "analysis.tool");
        row.push((
            "analysis.kind",
            crate::query::RowValue::Text(format!("{kind:?}")),
        ));
        if let Some(section) = report.sections.iter().find(|section| section.kind == kind) {
            row.push((
                "analysis.tool",
                crate::query::RowValue::List(section.tools.clone()),
            ));
        }
        row
    }
}

#[derive(Default)]
struct ViewState {
    query: String,
    /// Last filter that compiled. An invalid expression does not replace this.
    applied: String,
    query_error: Option<String>,
    selected: Option<(bool, u64)>,
    listing: super::listing_view::ListingState,
}

impl WorkspaceState {
    /// Filter the `kind` section to the row a note names.
    pub(crate) fn ask_row(&mut self, kind: AnalysisKind, query: String) {
        self.row_query = Some((kind, query));
    }

    /// Bring the tab that shows `kind` to the front.
    fn show(&mut self, kind: AnalysisKind) {
        (self.tab, self.file_info) = tabs::locate(kind, self.file_info);
    }

    /// The tab of `kind` in front, for the screenshot fixture.
    #[cfg(test)]
    pub(crate) fn show_category(&mut self, kind: AnalysisKind) {
        self.show(kind);
    }

    /// Carry out what a row's context menu chose.
    fn run_row(&mut self, command: Option<RowCommand>) {
        match command {
            Some(RowCommand::ShowInContent(offset)) => {
                self.content.go_to(offset);
                self.tab = Tab::Content;
            }
            Some(command) => self.rows.open(command),
            None => {}
        }
    }

    fn bind(&mut self, report_id: &str) {
        if self.report_id.as_deref() != Some(report_id) {
            let record_id = self.record_id.clone();
            let record_name = self.record_name.clone();
            let record_path = self.record_path.clone();
            let record_tags = self.record_tags.clone();
            let identities = self.identities.clone();
            *self = Self {
                report_id: Some(report_id.to_owned()),
                record_id,
                record_name,
                record_path,
                record_tags,
                identities,
                ..Self::default()
            };
        }
    }
}

pub(crate) fn workspace(
    ui: &mut egui::Ui,
    report: Option<&AnalysisReport>,
    state: &mut WorkspaceState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
    listing: Option<&Result<AnalysisListingPage, String>>,
) -> Option<ReportAction> {
    render(ui, report, state, preview, listing, None)
}

pub(crate) fn workspace_section(
    ui: &mut egui::Ui,
    report: Option<&AnalysisReport>,
    kind: AnalysisKind,
    state: &mut WorkspaceState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
    listing: Option<&Result<AnalysisListingPage, String>>,
) -> Option<ReportAction> {
    render(ui, report, state, preview, listing, Some(kind))
}

fn render(
    ui: &mut egui::Ui,
    report: Option<&AnalysisReport>,
    state: &mut WorkspaceState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
    listing: Option<&Result<AnalysisListingPage, String>>,
    forced: Option<AnalysisKind>,
) -> Option<ReportAction> {
    let Some(report) = report else {
        if forced.is_some() {
            super::no_report(ui, "No retained static analysis report");
        } else {
            super::no_report(ui, "No static analysis report for this run");
        }
        return None;
    };
    state.bind(&report.id);
    let mut action = None;
    // The report's chrome (file line, tabs, sub tabs) takes most of a short
    // window: the view keeps room for its content and scrolls as a whole
    // below that, instead of leaving the content a few rows.
    let wanted = if forced.is_some() {
        0.0
    } else {
        22.0 * ui.text_style_height(&egui::TextStyle::Body)
    };
    let height = ui.available_height().max(wanted);
    egui::ScrollArea::vertical()
        .id_salt("analysis-workspace")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_max_height(height);
            ui.set_min_height(height);
            if matches!(
                report.state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            ) && ui
                .button(egui_phosphor::regular::X)
                .on_hover_text("Cancel analysis")
                .clicked()
            {
                action = Some(ReportAction::Cancel(report.id.clone()));
            }
            super::progress_banner(ui, report);
            match forced {
                None => {
                    if let Some(next) = tabs::show(ui, report, state, preview, listing) {
                        action = Some(next);
                    }
                }
                Some(kind) => {
                    ui.separator();
                    let next = if kind == AnalysisKind::Regex {
                        tabs::regex_view(ui, report, state)
                    } else {
                        results(ui, report, state, listing, Some(kind))
                    };
                    if let Some(next) = next {
                        action = Some(next);
                    }
                }
            }
        });
    // The Content tab reads the same specimen preview as the bytes window.
    let bytes_visible = forced.is_some() || state.tab != Tab::Content;
    state.publish(ui.ctx(), report, forced);
    let windows = state.rows.show(
        ui.ctx(),
        (&report.id, forced),
        report,
        preview,
        bytes_visible,
        action.is_none(),
    );
    windows.or(action)
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod render_tests;

/// The rows a category has: its listing's, or those of Ghidra's listing when
/// the built-in disassembler made none, or the report's own rows.
fn row_count(report: &AnalysisReport, section: &AnalysisSection) -> u64 {
    match (&section.listing, report.ghidra_disassembly()) {
        (Some(listing), _) => listing.rows,
        (None, Some(ghidra)) if section.kind == AnalysisKind::Disassembly => ghidra.listing.rows,
        (None, _) => section.entries.len() as u64,
    }
}

fn results(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    listing: Option<&Result<AnalysisListingPage, String>>,
    forced: Option<AnalysisKind>,
) -> Option<ReportAction> {
    let Some(kind) = forced.or(state.kind) else {
        state.active_view = None;
        return overview(ui, report, state);
    };
    let Some(section) = report.sections.iter().find(|section| section.kind == kind) else {
        ui.label("This category has no retained result.");
        return None;
    };
    let mut action = None;
    let reason = section.reason();
    // The rest of the header: the row count, the tools and the buttons.
    let mut rest = |ui: &mut egui::Ui| {
        ui.label(format!(
            "{} rows",
            antinomie_monitor_core::analysis::detection::group_digits(row_count(report, section))
        ));
        let tools = tools(section);
        if !tools.is_empty() {
            ui.weak(tools.join(", "));
        }
        // The window's header already opens the result directory.
        if let Some(next) = export_controls(ui, report, Some(kind), forced.is_some()) {
            action = Some(next);
        }
        if forced.is_none()
            && ui
                .button(egui_phosphor::regular::ARROW_SQUARE_OUT)
                .on_hover_text("Open this category in a separate pane")
                .clicked()
        {
            action = Some(ReportAction::OpenSection {
                report_id: report.id.clone(),
                kind,
            });
        }
    };
    let head = |ui: &mut egui::Ui| {
        ui.strong(section_title(kind));
        crate::widgets::chip(ui, state_word(report, section), state_tone(section));
    };
    if let Some((text, _)) = &reason {
        // The reason follows the badge and may wrap, so nothing follows it on
        // its row; the count and buttons start the next one.
        let color = if section.state == antinomie_monitor_core::AnalysisSectionState::Unavailable {
            crate::theme::error()
        } else {
            crate::theme::warn()
        };
        ui.horizontal_wrapped(|ui| {
            head(ui);
            ui.label(egui::RichText::new(text).color(color));
        });
        ui.horizontal_wrapped(&mut rest);
    } else {
        ui.horizontal_wrapped(|ui| {
            head(ui);
            rest(ui);
        });
    }
    // An unavailable check's summary is its reason, already at the badge.
    if reason
        .as_ref()
        .is_none_or(|(text, _)| *text != section.summary)
    {
        ui.add(egui::Label::new(egui::RichText::new(&section.summary).weak()).wrap());
    }
    if let Some(next) = limits::notes(ui, report, section, reason.as_ref().is_some_and(|r| r.1)) {
        action = Some(next);
    }
    if section.summary.contains("Tools > Analysis tools")
        && section.state != antinomie_monitor_core::AnalysisSectionState::Complete
        && ui.button("Install analysis tools…").clicked()
    {
        action = Some(ReportAction::OpenAnalysisTools);
    }
    // The tab strip chooses the structure filter; a separate pane has only this.
    if kind == AnalysisKind::Structures && forced.is_some() {
        egui::ComboBox::from_id_salt("analysis-structure-filter")
            .selected_text(state.structure.label())
            .show_ui(ui, |ui| {
                for filter in std::iter::once(Structure::All).chain(Structure::FILTERS) {
                    ui.selectable_value(&mut state.structure, filter, filter.label());
                }
            });
    }
    let wanted = state
        .row_query
        .take_if(|(wanted, _)| *wanted == kind)
        .map(|(_, query)| query);
    if wanted.is_some() {
        state.structure = Structure::All;
    }
    let filter = if kind == AnalysisKind::Structures {
        state.structure
    } else {
        Structure::All
    };
    // Ghidra's listing stands in for built-in rows that could not be made.
    if section.listing.is_some()
        || (kind == AnalysisKind::Disassembly && report.ghidra_disassembly().is_some())
    {
        let record_context = state.record_context_for(report, kind);
        let view_key = if kind == AnalysisKind::Structures {
            format!("{kind:?}/{filter:?}/listing")
        } else {
            format!("{kind:?}/listing")
        };
        state.active_view = Some(view_key.clone());
        let view = state.views.entry(view_key).or_default();
        if let Some(query) = wanted {
            view.listing.query = query;
            view.listing.selected = None;
        }
        view.listing.set_record(record_context);
        view.listing.scope = (kind == AnalysisKind::Structures).then_some(filter);
        view.listing.content = forced.is_none();
        if let Some(next) =
            super::listing_view::show(ui, report, section, listing, &mut view.listing)
        {
            action = Some(next);
        }
        let command = view.listing.command.take();
        state.run_row(command);
        return action;
    }
    // A check that was stopped, or could not run, and has no rows says so once
    // (the chip, the summary and the warning above) instead of showing an empty
    // table with its headers.
    if section.entries.is_empty()
        && matches!(
            section.state,
            antinomie_monitor_core::AnalysisSectionState::Timeout
                | antinomie_monitor_core::AnalysisSectionState::Unavailable
        )
    {
        state.active_view = None;
        ui.weak(
            if section.state == antinomie_monitor_core::AnalysisSectionState::Timeout {
                "Nothing was found before the check was stopped."
            } else {
                "This check has no rows."
            },
        );
        return action;
    }
    let record_context = state.record_context_for(report, kind);
    let record_tags = state.record_tags.clone();
    let view_key = format!("{kind:?}/{filter:?}");
    state.active_view = Some(view_key.clone());
    let view = state.views.entry(view_key).or_default();
    if let Some(query) = wanted {
        view.query = query;
        view.selected = None;
    }
    if kind == AnalysisKind::Entropy {
        if let Some(index) = super::entropy::chart(ui, section, report.specimen_len) {
            view.selected = Some(records::identity(index, &section.entries[index]));
            state.rows.open_details(section.entries[index].clone());
        }
    }
    ui.horizontal(|ui| {
        crate::query::filter_edit_fields(
            ui,
            &mut view.query,
            "value contains http",
            ui.available_width(),
            &super::listing_view::listing_fields(kind),
            &record_tags,
        );
    });
    if let Some(error) = &view.query_error {
        crate::activity::error(ui, error);
    }
    let indices = visible(section, filter, view, &record_context);
    if view.query_error.is_none() {
        crate::query::remember_valid_filter(ui, &view.applied);
    }
    ui.label(format!(
        "{} matching / {} retained",
        crate::values::thousands(indices.len() as u64),
        crate::values::thousands(section.entries.len() as u64)
    ));
    let selected = view
        .selected
        .and_then(|id| {
            section.entries.iter().enumerate().find(|(index, entry)| {
                indices.contains(index) && records::identity(*index, entry) == id
            })
        })
        .map(|(_, entry)| entry);
    if view.selected.is_some() && selected.is_none() {
        view.selected = None;
    }
    let command = table(
        ui,
        section,
        filter,
        &indices,
        view,
        report,
        forced.is_none(),
    );
    state.run_row(command);
    action
}

fn overview(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
) -> Option<ReportAction> {
    let mut action = None;
    // Two columns need room for the categories card (name, state tag, row count
    // and button), which grows with the text size.
    let room = 50.0 * ui.text_style_height(&egui::TextStyle::Body);
    if ui.available_width() >= room {
        ui.columns(2, |columns| {
            egui::ScrollArea::vertical()
                .id_salt("analysis-overview-identity")
                .auto_shrink([false, false])
                .show(&mut columns[0], |ui| action = identity(ui, report));
            egui::ScrollArea::vertical()
                .id_salt("analysis-overview")
                .auto_shrink([false, false])
                .show(&mut columns[1], |ui| {
                    if let Some(next) = categories(ui, report, state) {
                        action = Some(next);
                    }
                });
        });
    } else {
        egui::ScrollArea::vertical()
            .id_salt("analysis-overview")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                action = identity(ui, report);
                ui.add_space(8.0);
                if let Some(next) = categories(ui, report, state) {
                    action = Some(next);
                }
            });
    }
    action
}

/// The report's state, the file's path and hashes, and its object format.
/// Triage › Properties shows the same identity for the run; the card links there.
fn identity(ui: &mut egui::Ui, report: &AnalysisReport) -> Option<ReportAction> {
    let mut action = None;
    if matches!(
        report.state,
        AnalysisState::Partial | AnalysisState::Unavailable | AnalysisState::Cancelled
    ) {
        if let Some(reason) = &report.reason {
            crate::activity::warning(ui, reason);
        } else if report.state == AnalysisState::Partial {
            // Partial because of its categories: name them.
            let names: Vec<&str> = report
                .sections
                .iter()
                .filter(|s| {
                    matches!(
                        s.state,
                        antinomie_monitor_core::AnalysisSectionState::Partial
                            | antinomie_monitor_core::AnalysisSectionState::Timeout
                            | antinomie_monitor_core::AnalysisSectionState::Unavailable
                    )
                })
                .map(|s| section_title(s.kind))
                .collect();
            if !names.is_empty() {
                crate::activity::info(
                    ui,
                    format!(
                        "Not every check completed: {}. Each one says why.",
                        names.join(", ")
                    ),
                );
            }
        }
    }
    let mut rows = vec![
        ("State".to_owned(), format!("{:?}", report.state)),
        ("Path".to_owned(), report.source_path.clone()),
    ];
    let metadata = report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Metadata);
    let field = |label: &str| {
        metadata?
            .entries
            .iter()
            .find(|entry| {
                entry.label.eq_ignore_ascii_case(label)
                    && matches!(
                        entry.record.as_ref().map(|record| &record.data),
                        Some(AnalysisData::Field { .. })
                    )
            })
            .map(|entry| entry.value.clone())
    };
    for label in ["MD5", "SHA-1"] {
        if let Some(value) = field(label) {
            rows.push((label.to_owned(), value));
        }
    }
    if let Some(hash) = &report.specimen_sha256 {
        rows.push(("SHA-256".to_owned(), hash.clone()));
    }
    if let Some(source) = report.specimen_source {
        rows.push(("Specimen source".to_owned(), source.label().to_owned()));
    }
    for label in [
        "Format",
        "Architecture",
        "Class",
        "Object kind",
        "Kind",
        "Endianness",
    ] {
        if let Some(value) = field(label) {
            rows.push((label.to_owned(), value));
        }
    }
    rows.push(("Report".to_owned(), report.id.clone()));
    crate::widgets::card(
        ui,
        "Identity",
        |ui| {
            if crate::widgets::link(ui, "Triage › Properties")
                .on_hover_text("The same identity and hashes with the file's other properties")
                .clicked()
            {
                action = Some(ReportAction::OpenTriageProperties);
            }
        },
        |ui| {
            egui::Grid::new("analysis-identity")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (label, value) in rows {
                        ui.strong(label.as_str());
                        ui.horizontal(|ui| {
                            if ui
                                .small_button(egui_phosphor::regular::COPY)
                                .on_hover_text(format!("Copy {label}"))
                                .clicked()
                            {
                                ui.ctx().copy_text(value.clone());
                            }
                            ui.add(egui::Label::new(egui::RichText::new(value).monospace()).wrap());
                        });
                        ui.end_row();
                    }
                });
        },
    );
    action
}

/// Every category the analysis can run: its state and size, a name that
/// opens its tab and the way to open it in a separate pane. One this report
/// does not have is listed disabled, with the reason as its tooltip.
fn categories(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
) -> Option<ReportAction> {
    use crate::widgets::Tone;
    let mut action = None;
    // Checks can be added to an analysis that is not being made.
    let finished = matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    );
    // One column of state tags, as wide as the longest word, so the tags line
    // up from one category to the next; the counts and buttons line up too.
    let tag_width = crate::widgets::chip_width(ui, TAG_WORDS);
    let regex_total = state.regex.total();
    // As wide as the longest count shown, so a narrow pane keeps it in view.
    let rows_width = {
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let widest = report
            .sections
            .iter()
            .map(|section| row_count(report, section))
            .chain(regex_total)
            .max()
            .unwrap_or(0);
        let text = format!(
            "{} rows",
            antinomie_monitor_core::analysis::detection::group_digits(widest)
        );
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(text, font, egui::Color32::PLACEHOLDER)
                .size()
                .x
        })
    };
    // The title column fits the longest title (a reason a check is not
    // complete needs a little more); a narrow pane cuts titles with an
    // ellipsis (the full title is one hover away) instead of squeezing them.
    let name_width = {
        let font = egui::TextStyle::Button.resolve(ui.style());
        let longest = ui.fonts(|fonts| {
            ALL_KINDS
                .iter()
                .map(|kind| {
                    fonts
                        .layout_no_wrap(
                            section_title(*kind).to_owned(),
                            font.clone(),
                            egui::Color32::PLACEHOLDER,
                        )
                        .size()
                        .x
                })
                .fold(0.0_f32, f32::max)
        }) + 2.0 * ui.spacing().button_padding.x;
        let needs_reason = report
            .sections
            .iter()
            .any(|section| section.reason().is_some());
        let wanted = if needs_reason {
            longest.max(220.0)
        } else {
            longest
        };
        let others = tag_width
            + rows_width
            + ui.spacing().interact_size.x
            + 3.0 * 12.0
            + 2.0 * ui.spacing().item_spacing.x
            + 24.0;
        wanted.min((ui.available_width() - others).max(90.0))
    };
    crate::widgets::card(
        ui,
        "Categories",
        |_| {},
        |ui| {
            egui::Grid::new("analysis-categories")
                .num_columns(4)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    for kind in ALL_KINDS {
                        let Some(section) =
                            report.sections.iter().find(|section| section.kind == kind)
                        else {
                            ui.add_enabled(
                                false,
                                egui::Label::new(section_title(kind)).truncate(),
                            )
                                .on_disabled_hover_text(NOT_REQUESTED);
                            crate::widgets::chip_wide(ui, "Not requested", Tone::Neutral, tag_width);
                            ui.label("");
                            if run_button(
                                ui,
                                finished,
                                "Run this check now; the rest of the analysis is not repeated",
                            ) {
                                action = Some(ReportAction::RunCheck {
                                    report_id: report.id.clone(),
                                    kind,
                                });
                            }
                            ui.end_row();
                            continue;
                        };
                        let clicked = ui
                            .vertical(|ui| {
                                // Why a check is not complete stands under its name.
                                ui.set_width(name_width);
                                let clicked = ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new(section_title(kind))
                                                .color(crate::theme::palette().accent),
                                        )
                                        .frame(false)
                                        .truncate(),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(format!(
                                        "{}\n{}",
                                        section_title(kind),
                                        section.summary
                                    ))
                                    .clicked();
                                if let Some((text, _)) = section.reason() {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(text)
                                                .small()
                                                .color(crate::theme::warn()),
                                        )
                                        .wrap(),
                                    );
                                }
                                clicked
                            })
                            .inner;
                        if clicked {
                            state.show(kind);
                        }
                        let tag = crate::widgets::chip_wide(
                            ui,
                            state_word(report, section),
                            state_tone(section),
                            tag_width,
                        );
                        // Why a check is not complete is one hover away.
                        if !section.summary.is_empty()
                            && section.state != antinomie_monitor_core::AnalysisSectionState::Complete
                        {
                            tag.on_hover_text(&section.summary);
                        }
                        // The regex matches are read from the strings: they
                        // have a count once the matches have been scanned.
                        let rows = if kind == AnalysisKind::Regex {
                            regex_total
                        } else {
                            Some(row_count(report, section))
                        };
                        ui.allocate_ui_with_layout(
                            egui::vec2(rows_width, ui.spacing().interact_size.y),
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if let Some(rows) = rows {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} rows",
                                            antinomie_monitor_core::analysis::detection::group_digits(rows)
                                        ))
                                        .monospace(),
                                    );
                                }
                            },
                        );
                        if ui
                            .button(egui_phosphor::regular::ARROW_SQUARE_OUT)
                            .on_hover_text("Open category in a separate pane")
                            .clicked()
                        {
                            action = Some(ReportAction::OpenSection {
                                report_id: report.id.clone(),
                                kind,
                            });
                        }
                        ui.end_row();
                    }
                });
        },
    );
    action
}

/// Every word a category's state tag can say, to size the tag column.
const TAG_WORDS: &[&str] = &[
    "Complete",
    "Partial",
    "Unavailable",
    "Timeout",
    "Pending",
    "Running…",
    "Queued…",
    "Waiting…",
    "Not requested",
];

/// The small Run button of a category; true when it was pressed.
fn run_button(ui: &mut egui::Ui, enabled: bool, hover: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new("Run").small())
        .on_hover_text(hover)
        .on_disabled_hover_text("Wait for the analysis to finish")
        .clicked()
}

/// Why a category that is not in the report cannot be opened.
pub(super) const NOT_REQUESTED: &str =
    "Not part of this analysis; Run in Overview > Categories adds it without starting over";

const ALL_KINDS: [AnalysisKind; 14] = [
    AnalysisKind::Metadata,
    AnalysisKind::Structures,
    AnalysisKind::Strings,
    AnalysisKind::Regex,
    AnalysisKind::Entropy,
    AnalysisKind::Hardening,
    AnalysisKind::Rules,
    AnalysisKind::Identification,
    AnalysisKind::Capabilities,
    AnalysisKind::Disassembly,
    AnalysisKind::Decompilation,
    AnalysisKind::Embedded,
    AnalysisKind::Floss,
    AnalysisKind::Unpacking,
];

fn state_tone(section: &AnalysisSection) -> crate::widgets::Tone {
    use crate::widgets::Tone;
    use antinomie_monitor_core::AnalysisSectionState as S;
    match section.state {
        S::Complete => Tone::Good,
        S::Partial | S::Timeout => Tone::Warn,
        S::Unavailable => Tone::Error,
        S::Pending | S::Running => Tone::Neutral,
    }
}

/// The specimen's name: the record's when it has one, else the path's last part.
fn file_name(report: &AnalysisReport, state: &WorkspaceState) -> String {
    if !state.record_name.is_empty() {
        return state.record_name.clone();
    }
    report
        .source_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(&report.source_path)
        .to_owned()
}

fn visible(
    section: &AnalysisSection,
    filter: Structure,
    view: &mut ViewState,
    context: &[(&'static str, crate::query::RowValue)],
) -> Vec<usize> {
    let fields = super::listing_view::listing_fields(section.kind);
    let draft = crate::query::compile_table(&view.query, &fields);
    if draft.error.is_some() {
        view.query_error.clone_from(&draft.error);
    } else {
        view.applied.clone_from(&view.query);
        view.query_error = None;
    }
    let compiled = crate::query::compile_table(&view.applied, &fields);
    let query = if crate::query::structured(&view.applied) {
        String::new()
    } else {
        view.applied.to_lowercase()
    };
    let indices: Vec<_> = section
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !is_provenance(entry)
                && filter.accepts(entry)
                && (compiled.keep_table(&super::listing_view::listing_row_with(entry, context))
                    || (!crate::query::structured(&view.applied)
                        && (query.is_empty() || records::searchable(entry).contains(&query))))
        })
        .map(|(index, _)| index)
        .collect();
    indices
}

/// Rows older reports used to name the engine or a tool version; they are
/// shown as the category's tools instead.
fn is_provenance(entry: &AnalysisEntry) -> bool {
    matches!(
        entry.label.as_str(),
        "Engine" | "objdump version" | "file version" | "readelf version"
    ) && entry
        .record
        .as_ref()
        .is_none_or(|record| matches!(record.data, AnalysisData::Field { .. }))
}

/// The category's tools, including those older reports kept as rows.
fn tools(section: &AnalysisSection) -> Vec<String> {
    // Reports from before the rename credit the built-in analysis by its old name.
    let mut tools: Vec<String> = section
        .tools
        .iter()
        .map(
            |tool| match tool.strip_prefix("Antinomie byte triage 2 (") {
                Some(version) => format!("Built-in analysis ({version}"),
                None => tool.clone(),
            },
        )
        .collect();
    for entry in section.entries.iter().filter(|entry| is_provenance(entry)) {
        if !tools.contains(&entry.value) {
            tools.push(entry.value.clone());
        }
    }
    tools
}

/// A category's state as a word; one without a result says "Running…"
/// while its report is still being analyzed.
fn state_word(report: &AnalysisReport, section: &AnalysisSection) -> &'static str {
    match section.state {
        antinomie_monitor_core::AnalysisSectionState::Pending if super::in_progress(report) => {
            super::pending_word(report.state)
        }
        antinomie_monitor_core::AnalysisSectionState::Pending => "Pending",
        antinomie_monitor_core::AnalysisSectionState::Running => "Running…",
        antinomie_monitor_core::AnalysisSectionState::Complete => "Complete",
        antinomie_monitor_core::AnalysisSectionState::Partial => "Partial",
        antinomie_monitor_core::AnalysisSectionState::Unavailable => "Unavailable",
        antinomie_monitor_core::AnalysisSectionState::Timeout => "Timeout",
    }
}

fn selected_entry<'a>(section: &'a AnalysisSection, view: &ViewState) -> Option<&'a AnalysisEntry> {
    let id = view.selected?;
    section
        .entries
        .iter()
        .enumerate()
        .find(|(index, entry)| records::identity(*index, entry) == id)
        .map(|(_, entry)| entry)
}

/// The retained rows as a table; a row's context menu may ask for a command.
fn table(
    ui: &mut egui::Ui,
    section: &AnalysisSection,
    filter: Structure,
    indices: &[usize],
    view: &mut ViewState,
    report: &AnalysisReport,
    content: bool,
) -> Option<RowCommand> {
    let legacy = indices
        .iter()
        .all(|&index| section.entries[index].record.is_none());
    let columns = records::columns(section.kind, filter, legacy);
    let height = ui.text_style_height(&egui::TextStyle::Body) + 12.0;
    let mut command = None;
    let table_id = format!("analysis-{:?}-{filter:?}", section.kind);
    let order = crate::table_sort::order(ui.ctx(), &table_id, indices.len(), |position, a, b| {
        columns[position].compare(&section.entries[indices[a]], &section.entries[indices[b]])
    });
    ui.scope(|ui| {
        // Rows select on click; text selection would swallow it.
        ui.style_mut().interaction.selectable_labels = false;
        let max_height = ui.available_height().max(height);
        crate::widgets::table::begin(ui);
        let mut table = FitBuilder::new(ui)
            .id_salt("analysis-table")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .max_scroll_height(max_height);
        for (position, &column) in columns.iter().enumerate() {
            let width = if column == Column::Value {
                300.0
            } else {
                145.0
            };
            // The last column takes the width the other columns leave.
            table = table.column(if position + 1 == columns.len() {
                TableColumn::rest(80.0).at_least(width).clip(true)
            } else {
                TableColumn::flex(width).at_least(90.0).clip(true)
            });
        }
        table
            .header(height, |mut header| {
                for (position, &column) in columns.iter().enumerate() {
                    header.col(|ui| {
                        crate::table_sort::header(ui, &table_id, position, column.label())
                    });
                }
            })
            .body(|body| {
                body.rows(height, indices.len(), |mut row| {
                    let index = indices[order[row.index()]];
                    let entry = &section.entries[index];
                    let id = records::identity(index, entry);
                    row.set_selected(view.selected == Some(id));
                    for &column in columns {
                        row.col(|ui| {
                            let text = super::meaning::shown_text(
                                section.kind,
                                column,
                                entry,
                                &column.text(entry),
                            );
                            ui.add(
                                egui::Label::new(super::meaning::meaning_text(
                                    section.kind,
                                    column,
                                    entry,
                                    text.clone(),
                                ))
                                .truncate(),
                            )
                            .on_hover_text(text);
                        });
                    }
                    row.response().context_menu(|ui| {
                        let cells: Vec<_> = columns
                            .iter()
                            .map(|column| (column.label(), column.text(entry)))
                            .collect();
                        if let Some(next) =
                            row_menu::menu(ui, &cells, entry, report, section.kind, content)
                        {
                            command = Some(next);
                        }
                    });
                    let response = row.response();
                    if response.clicked() || response.secondary_clicked() {
                        view.selected = Some(id);
                    }
                });
            });
    });
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{AnalysisRecord, AnalysisSectionState};
    fn section() -> AnalysisSection {
        AnalysisSection {
            disassembly: None,
            kind: AnalysisKind::Strings,
            state: AnalysisSectionState::Partial,
            summary: "Retained text is bounded".into(),
            tools: Vec::new(),
            listing: None,
            entries: [16, 2, 32]
                .into_iter()
                .map(|offset| AnalysisEntry {
                    label: "string".into(),
                    value: format!("value{offset}"),
                    offset: Some(offset),
                    record: Some(AnalysisRecord {
                        revision: 1,
                        id: offset,
                        location: None,
                        data: AnalysisData::String {
                            encoding: "ASCII".into(),
                            byte_len: offset,
                            retained_len: 7,
                        },
                    }),
                })
                .collect(),
            limits: Vec::new(),
        }
    }
    #[test]
    fn filter_preserves_selected_record_identity() {
        let section = section();
        let mut view = ViewState {
            selected: Some((true, 16)),
            ..Default::default()
        };
        assert_eq!(visible(&section, Structure::All, &mut view, &[]), [0, 1, 2]);
        assert_eq!(selected_entry(&section, &view).unwrap().offset, Some(16));
        view.query = "value2".into();
        assert_eq!(visible(&section, Structure::All, &mut view, &[]), [1]);
        assert_eq!(view.selected, Some((true, 16)));
    }
    #[test]
    fn a_waiting_check_is_worded_apart_from_the_one_running() {
        let mut report = AnalysisReport {
            id: "words".into(),
            state: AnalysisState::Running,
            source_path: "/bin/true".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: vec![
                AnalysisSection::new(AnalysisKind::Strings),
                AnalysisSection::new(AnalysisKind::Capabilities),
            ],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
        };
        report.sections[1].state = AnalysisSectionState::Running;
        let words: Vec<_> = report
            .sections
            .iter()
            .map(|section| state_word(&report, section))
            .collect();
        assert_eq!(words, ["Waiting…", "Running…"]);
        report.state = AnalysisState::Queued;
        assert_eq!(state_word(&report, &report.sections[0]), "Queued…");
        report.state = AnalysisState::Partial;
        assert_eq!(state_word(&report, &report.sections[0]), "Pending");
    }
    #[test]
    fn switching_report_resets_navigation_selection_and_preview() {
        let mut state = WorkspaceState::default();
        state.bind("first");
        state.kind = Some(AnalysisKind::Strings);
        state.views.insert(
            "strings".into(),
            ViewState {
                selected: Some((true, 1)),
                ..Default::default()
            },
        );
        state.bind("second");
        assert!(state.kind.is_none());
        assert!(state.views.is_empty());
    }
}
