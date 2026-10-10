//! Native retained-evidence workspace; all acquisition remains outside rendering.
use super::{
    records::{self, Column, Structure},
    section_title, ReportAction,
};
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListingPage, AnalysisReport,
    AnalysisSection, AnalysisSpecimenPage, AnalysisState,
};
use eframe::egui;
use egui_extras::{Column as TableColumn, TableBuilder};
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct WorkspaceState {
    report_id: Option<String>,
    kind: Option<AnalysisKind>,
    structure: Structure,
    views: BTreeMap<String, ViewState>,
    active_view: Option<String>,
}

#[derive(Default)]
struct ViewState {
    query: String,
    sort: Option<(Column, bool)>,
    selected: Option<(bool, u64)>,
    detail_tab: u8,
    requested: Option<(u64, usize)>,
    listing: super::listing_view::ListingState,
}

impl WorkspaceState {
    fn bind(&mut self, report_id: &str) {
        if self.report_id.as_deref() != Some(report_id) {
            *self = Self {
                report_id: Some(report_id.to_owned()),
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
            ui.label("No retained static analysis report.");
        } else {
            super::no_report(ui, true);
        }
        return None;
    };
    state.bind(&report.id);
    let mut action = None;
    ui.horizontal(|ui| {
        ui.strong(format!("{:?}", report.state));
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
        ui.add(egui::Label::new(&report.source_path).truncate())
            .on_hover_text(format!(
                "{}\nReport: {}\nSHA-256: {}\nSpecimen: {}",
                report.source_path,
                report.id,
                report.specimen_sha256.as_deref().unwrap_or("Unavailable"),
                report
                    .specimen_len
                    .map(|n| format!("{n} octets"))
                    .unwrap_or_else(|| "Unavailable".into())
            ));
    });
    if let Some(reason) = &report.reason {
        ui.add(
            egui::Label::new(egui::RichText::new(reason).color(crate::theme::muted())).truncate(),
        )
        .on_hover_text(reason);
    }
    super::progress_banner(ui, report);
    ui.separator();
    if forced.is_none() && ui.available_width() >= 900.0 {
        ui.horizontal_top(|ui| {
            let height = ui.available_height();
            ui.allocate_ui_with_layout(
                egui::vec2(185.0, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("analysis-categories")
                        .show(ui, |ui| navigation(ui, report, state));
                },
            );
            ui.separator();
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    if let Some(next) = results(ui, report, state, preview, listing, None) {
                        action = Some(next);
                    }
                },
            );
        });
    } else {
        if forced.is_none() {
            egui::ComboBox::from_id_salt("analysis-category")
                .selected_text(state.kind.map(section_title).unwrap_or("Overview"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.kind, None, "Overview");
                    for section in &report.sections {
                        ui.selectable_value(
                            &mut state.kind,
                            Some(section.kind),
                            section_title(section.kind),
                        );
                    }
                });
        }
        if let Some(next) = results(ui, report, state, preview, listing, forced) {
            action = Some(next);
        }
    }
    action
}

fn navigation(ui: &mut egui::Ui, report: &AnalysisReport, state: &mut WorkspaceState) {
    if ui
        .selectable_label(state.kind.is_none(), "Overview")
        .clicked()
    {
        state.kind = None;
    }
    for section in &report.sections {
        if section.kind == AnalysisKind::Structures {
            egui::CollapsingHeader::new(nav_title(report, section))
                .id_salt("Structures")
                .default_open(true)
                .show(ui, |ui| {
                    if ui
                        .add(
                            egui::Button::new("All structures")
                                .selected(
                                    state.kind == Some(section.kind)
                                        && state.structure == Structure::All,
                                )
                                .frame(false)
                                .truncate(),
                        )
                        .clicked()
                    {
                        state.kind = Some(section.kind);
                        state.structure = Structure::All;
                    }
                    for filter in Structure::FILTERS {
                        if ui
                            .add(
                                egui::Button::new(filter.label())
                                    .selected(
                                        state.kind == Some(section.kind)
                                            && state.structure == filter,
                                    )
                                    .frame(false)
                                    .truncate(),
                            )
                            .clicked()
                        {
                            state.kind = Some(section.kind);
                            state.structure = filter;
                        }
                    }
                });
        } else if ui
            .add(
                egui::Button::new(nav_title(report, section))
                    .selected(state.kind == Some(section.kind))
                    .frame(false)
                    .truncate(),
            )
            .on_hover_text(state_word(report, section))
            .clicked()
        {
            state.kind = Some(section.kind);
        }
    }
}

/// A category's name, marked with an hourglass while it is still running.
fn nav_title(report: &AnalysisReport, section: &AnalysisSection) -> String {
    if super::in_progress(report)
        && section.state == antinomie_monitor_core::AnalysisSectionState::Pending
    {
        format!(
            "{} {}",
            egui_phosphor::regular::HOURGLASS_MEDIUM,
            section_title(section.kind)
        )
    } else {
        section_title(section.kind).to_owned()
    }
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod render_tests;

fn results(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
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
    ui.horizontal(|ui| {
        ui.strong(section_title(kind));
        let rows = section
            .listing
            .as_ref()
            .map_or(section.entries.len() as u64, |listing| listing.rows);
        ui.label(format!("{} · {rows} rows", state_word(report, section)));
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
    });
    ui.add(egui::Label::new(&section.summary).wrap());
    if section.summary.contains("Tools > Analysis tools")
        && section.state != antinomie_monitor_core::AnalysisSectionState::Complete
        && ui.button("Install analysis tools…").clicked()
    {
        action = Some(ReportAction::OpenAnalysisTools);
    }
    let tools = tools(section);
    if !tools.is_empty() {
        ui.add(
            egui::Label::new(egui::RichText::new(format!("Tools: {}", tools.join(", "))).weak())
                .wrap(),
        );
    }
    if section.listing.is_some() && kind != AnalysisKind::Structures {
        let view_key = format!("{kind:?}/listing");
        state.active_view = Some(view_key.clone());
        let view = state.views.entry(view_key).or_default();
        let wide = ui.available_width() >= 800.0;
        if wide {
            ui.horizontal_top(|ui| {
                let height = ui.available_height();
                let width = (ui.available_width() * 0.7).max(300.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        if let Some(next) = super::listing_view::show(
                            ui,
                            report,
                            section,
                            listing,
                            &mut view.listing,
                        ) {
                            action = Some(next);
                        }
                    },
                );
                ui.separator();
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        let selected = view
                            .listing
                            .selected
                            .as_ref()
                            .map(|(_, entry)| entry.clone());
                        if let Some(next) = detail(ui, report, selected.as_ref(), view, preview) {
                            action = Some(next);
                        }
                    },
                );
            });
        } else {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut view.detail_tab, 0, "Results");
                ui.selectable_value(&mut view.detail_tab, 1, "Details");
                ui.selectable_value(&mut view.detail_tab, 2, "Bytes");
            });
            if view.detail_tab == 0 {
                if let Some(next) =
                    super::listing_view::show(ui, report, section, listing, &mut view.listing)
                {
                    action = Some(next);
                }
            } else {
                let selected = view
                    .listing
                    .selected
                    .as_ref()
                    .map(|(_, entry)| entry.clone());
                if let Some(next) = detail(ui, report, selected.as_ref(), view, preview) {
                    action = Some(next);
                }
            }
        }
        return action;
    }
    if kind == AnalysisKind::Structures {
        egui::ComboBox::from_id_salt("analysis-structure-filter")
            .selected_text(state.structure.label())
            .show_ui(ui, |ui| {
                for filter in std::iter::once(Structure::All).chain(Structure::FILTERS) {
                    ui.selectable_value(&mut state.structure, filter, filter.label());
                }
            });
    }
    let filter = if kind == AnalysisKind::Structures {
        state.structure
    } else {
        Structure::All
    };
    let view_key = format!("{kind:?}/{filter:?}");
    let changed_view = state.active_view.as_ref() != Some(&view_key);
    state.active_view = Some(view_key.clone());
    let view = state.views.entry(view_key).or_default();
    if changed_view {
        view.requested = None;
    }
    if kind == AnalysisKind::Entropy {
        if let Some(index) = super::entropy::chart(ui, section, report.specimen_len) {
            view.selected = Some(records::identity(index, &section.entries[index]));
            view.requested = None;
            view.detail_tab = 1;
        }
    }
    ui.horizontal(|ui| {
        let label = ui.label("Search");
        ui.add(
            egui::TextEdit::singleline(&mut view.query)
                .desired_width(ui.available_width())
                .hint_text("Filter retained rows"),
        )
        .labelled_by(label.id);
    });
    let indices = visible(section, filter, view);
    ui.label(format!(
        "{} matching / {} retained",
        indices.len(),
        section.entries.len()
    ));
    let selected = view
        .selected
        .and_then(|id| {
            section
                .entries
                .iter()
                .enumerate()
                .find(|(index, entry)| records::identity(*index, entry) == id)
        })
        .map(|(_, entry)| entry);
    if view.selected.is_some() && selected.is_none() {
        view.selected = None;
        view.requested = None;
    }
    let wide = ui.available_width() >= 800.0;
    if wide {
        ui.horizontal_top(|ui| {
            let height = ui.available_height();
            let width = (ui.available_width() - 310.0).max(200.0);
            ui.allocate_ui_with_layout(
                egui::vec2(width, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| table(ui, section, filter, &indices, view),
            );
            ui.separator();
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    let selected = selected_entry(section, view);
                    if let Some(next) = detail(ui, report, selected, view, preview) {
                        action = Some(next);
                    }
                },
            );
        });
    } else {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut view.detail_tab, 0, "Results");
            ui.selectable_value(&mut view.detail_tab, 1, "Details");
            ui.selectable_value(&mut view.detail_tab, 2, "Bytes");
        });
        if view.detail_tab == 0 {
            table(ui, section, filter, &indices, view);
        } else {
            let selected = selected_entry(section, view);
            if let Some(next) = detail(ui, report, selected, view, preview) {
                action = Some(next);
            }
        }
    }
    action
}

fn overview(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
) -> Option<ReportAction> {
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("analysis-overview")
        .show(ui, |ui| {
            identity_value(ui, "Report", &report.id);
            if let Some(len) = report.specimen_len {
                ui.label(format!("Specimen: {len} octets"));
            }
            if let Some(hash) = &report.specimen_sha256 {
                identity_value(ui, "SHA-256", hash);
            }
            if let Some(metadata) = report
                .sections
                .iter()
                .find(|section| section.kind == AnalysisKind::Metadata)
            {
                for entry in &metadata.entries {
                    if matches!(
                        entry.record.as_ref().map(|record| &record.data),
                        Some(AnalysisData::Field { .. })
                    ) && [
                        "Format",
                        "Architecture",
                        "Class",
                        "Object kind",
                        "Kind",
                        "Endianness",
                    ]
                    .iter()
                    .any(|label| entry.label.eq_ignore_ascii_case(label))
                    {
                        identity_value(ui, &entry.label, &entry.value);
                    }
                }
            }
            for section in &report.sections {
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(false, section_title(section.kind))
                        .clicked()
                    {
                        state.kind = Some(section.kind);
                    }
                    ui.label(format!(
                        "{} / {} rows",
                        state_word(report, section),
                        section.entries.len()
                    ));
                    if ui
                        .button(egui_phosphor::regular::ARROW_SQUARE_OUT)
                        .on_hover_text("Open category in a separate pane")
                        .clicked()
                    {
                        action = Some(ReportAction::OpenSection {
                            report_id: report.id.clone(),
                            kind: section.kind,
                        });
                    }
                });
                ui.add(egui::Label::new(&section.summary).truncate())
                    .on_hover_text(&section.summary);
            }
        });
    action
}

fn visible(section: &AnalysisSection, filter: Structure, view: &ViewState) -> Vec<usize> {
    let query = view.query.to_lowercase();
    let mut indices: Vec<_> = section
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !is_provenance(entry)
                && filter.accepts(entry)
                && (query.is_empty() || records::searchable(entry).contains(&query))
        })
        .map(|(index, _)| index)
        .collect();
    if let Some((column, descending)) = view.sort {
        indices.sort_by(|&left, &right| {
            let order = column.compare(&section.entries[left], &section.entries[right]);
            let order = if descending { order.reverse() } else { order };
            order.then_with(|| left.cmp(&right))
        });
    }
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
    let mut tools = section.tools.clone();
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
        antinomie_monitor_core::AnalysisSectionState::Complete => "Complete",
        antinomie_monitor_core::AnalysisSectionState::Partial => "Partial",
        antinomie_monitor_core::AnalysisSectionState::Unavailable => "Unavailable",
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

fn table(
    ui: &mut egui::Ui,
    section: &AnalysisSection,
    filter: Structure,
    indices: &[usize],
    view: &mut ViewState,
) {
    let legacy = indices
        .iter()
        .all(|&index| section.entries[index].record.is_none());
    let columns = records::columns(section.kind, filter, legacy);
    let height = ui.text_style_height(&egui::TextStyle::Body) + 12.0;
    egui::ScrollArea::horizontal()
        .id_salt("analysis-table-horizontal")
        .show(ui, |ui| {
            let max_height = ui.available_height().max(height);
            let mut table = TableBuilder::new(ui)
                .id_salt("analysis-table")
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .max_scroll_height(max_height);
            for &column in columns {
                table = table.column(
                    TableColumn::initial(if column == Column::Value {
                        300.0
                    } else {
                        145.0
                    })
                    .at_least(90.0)
                    .clip(true),
                );
            }
            table
                .header(height, |mut header| {
                    for &column in columns {
                        header.col(|ui| {
                            let suffix = view
                                .sort
                                .filter(|(sort, _)| *sort == column)
                                .map(|(_, descending)| if descending { " v" } else { " ^" })
                                .unwrap_or("");
                            if ui
                                .add(
                                    egui::Label::new(format!("{}{suffix}", column.label()))
                                        .sense(egui::Sense::click()),
                                )
                                .on_hover_text(format!("Sort by {}", column.label()))
                                .clicked()
                            {
                                view.sort = Some((
                                    column,
                                    view.sort.is_some_and(|(sort, descending)| {
                                        sort == column && !descending
                                    }),
                                ));
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(height, indices.len(), |mut row| {
                        let index = indices[row.index()];
                        let entry = &section.entries[index];
                        let id = records::identity(index, entry);
                        row.set_selected(view.selected == Some(id));
                        let mut clicked = false;
                        for &column in columns {
                            row.col(|ui| {
                                let text = column.text(entry);
                                clicked |= ui
                                    .add(
                                        egui::Label::new(&text)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text(text)
                                    .clicked();
                            });
                        }
                        if clicked || row.response().clicked() {
                            if view.selected != Some(id) {
                                view.requested = None;
                            }
                            view.selected = Some(id);
                        }
                    });
                });
        });
}

fn copy_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.strong(label);
        if ui
            .button(egui_phosphor::regular::COPY)
            .on_hover_text(format!("Copy full {label}"))
            .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
    });
    ui.add(egui::Label::new(value).wrap());
}

fn identity_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.strong(label);
        if ui
            .button(egui_phosphor::regular::COPY)
            .on_hover_text(format!("Copy full {label}"))
            .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
        ui.add(egui::Label::new(value).truncate())
            .on_hover_text(value);
    });
}

fn detail(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    entry: Option<&AnalysisEntry>,
    view: &mut ViewState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
) -> Option<ReportAction> {
    let Some(entry) = entry else {
        ui.label("No row selected.");
        return None;
    };
    let mut action = None;
    egui::ScrollArea::both()
        .id_salt("analysis-item-detail")
        .show(ui, |ui| {
            if view.detail_tab != 2 {
                copy_value(ui, &entry.label, &entry.value);
                if let Some(record) = &entry.record {
                    ui.label(format!("Record {}", record.id));
                    if let Some(location) = &record.location {
                        ui.monospace(format!("{:?}: 0x{:x}", location.kind, location.value));
                        if let Some(range) = location.file_range {
                            ui.monospace(format!(
                                "File range: 0x{:x} + {} octets",
                                range.offset, range.len
                            ));
                        }
                    }
                    if let AnalysisData::Section {
                        raw_flags, flags, ..
                    } = &record.data
                    {
                        copy_value(ui, "Raw flags", raw_flags);
                        copy_value(ui, "Decoded flags", &flags.join(" | "));
                    }
                    for column in [
                        Column::Address,
                        Column::VirtualSize,
                        Column::FileSize,
                        Column::Library,
                        Column::Ordinal,
                        Column::Encoding,
                        Column::Size,
                        Column::Retained,
                        Column::Entropy,
                        Column::Scope,
                        Column::Kind,
                        Column::Defined,
                    ] {
                        let value = column.text(entry);
                        if value != "-" {
                            copy_value(ui, column.label(), &value);
                        }
                    }
                    if let AnalysisData::Property {
                        observed, evidence, ..
                    } = &record.data
                    {
                        copy_value(ui, "Observed", observed);
                        copy_value(ui, "Evidence", evidence);
                    }
                } else {
                    ui.label("Legacy field/value evidence");
                    if let Some(offset) = entry.offset {
                        ui.monospace(format!("File offset: 0x{offset:x}"));
                    }
                }
                ui.separator();
            }
            let Some(range) = records::file_range(entry, report.specimen_len) else {
                ui.label("No proven retained file range for byte preview.");
                return;
            };
            let data_len = usize::try_from(range.len.min(256)).unwrap_or(256);
            if ui
                .button(format!("{} Bytes", egui_phosphor::regular::EYE))
                .on_hover_text("Read bounded retained specimen bytes")
                .clicked()
            {
                view.requested = Some((range.offset, data_len));
                action = Some(ReportAction::ReadSpecimen {
                    report_id: report.id.clone(),
                    offset: range.offset,
                    data_len,
                });
            }
            let Some((offset, data_len)) = view.requested else {
                return;
            };
            ui.horizontal(|ui| {
                let previous = offset.saturating_sub(256).max(range.offset);
                let next = offset
                    .checked_add(data_len as u64)
                    .filter(|next| *next < range.offset + range.len);
                let mut target = None;
                if ui
                    .add_enabled(
                        offset > range.offset,
                        egui::Button::new(egui_phosphor::regular::ARROW_LEFT),
                    )
                    .on_hover_text("Previous specimen page")
                    .clicked()
                {
                    target = Some(previous);
                }
                if ui
                    .add_enabled(
                        next.is_some(),
                        egui::Button::new(egui_phosphor::regular::ARROW_RIGHT),
                    )
                    .on_hover_text("Next specimen page")
                    .clicked()
                {
                    target = next;
                }
                if let Some(offset) = target {
                    let data_len = usize::try_from((range.offset + range.len - offset).min(256))
                        .unwrap_or(256);
                    view.requested = Some((offset, data_len));
                    action = Some(ReportAction::ReadSpecimen {
                        report_id: report.id.clone(),
                        offset,
                        data_len,
                    });
                }
            });
            let (offset, data_len) = view.requested.unwrap_or((offset, data_len));
            ui.monospace(format!("File offset 0x{offset:x} / {data_len} octets"));
            match preview {
                Some(Ok(page)) if preview_matches(page, report, offset, data_len) => {
                    for (index, chunk) in page.data.chunks(16).enumerate() {
                        let hex = chunk
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let text: String = chunk
                            .iter()
                            .map(|&byte| {
                                if byte.is_ascii_graphic() || byte == b' ' {
                                    char::from(byte)
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        ui.monospace(format!(
                            "{:08x}  {:47}  {}",
                            offset + index as u64 * 16,
                            hex,
                            text
                        ));
                    }
                }
                Some(Err(reason)) => {
                    ui.colored_label(crate::theme::error(), reason);
                }
                _ => {
                    ui.label("Awaiting matching specimen preview.");
                }
            }
        });
    action
}

fn preview_matches(
    page: &AnalysisSpecimenPage,
    report: &AnalysisReport,
    offset: u64,
    data_len: usize,
) -> bool {
    page.report_id == report.id
        && page.offset == offset
        && page.data.len() == data_len
        && Some(page.total_len) == report.specimen_len
        && offset
            .checked_add(data_len as u64)
            .is_some_and(|end| end <= page.total_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{AnalysisRecord, AnalysisSectionState};
    fn section() -> AnalysisSection {
        AnalysisSection {
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
        }
    }
    #[test]
    fn filter_sort_preserve_selected_record_identity() {
        let section = section();
        let mut view = ViewState {
            selected: Some((true, 16)),
            sort: Some((Column::Size, false)),
            ..Default::default()
        };
        assert_eq!(visible(&section, Structure::All, &view), [1, 0, 2]);
        assert_eq!(selected_entry(&section, &view).unwrap().offset, Some(16));
        view.query = "value2".into();
        assert_eq!(visible(&section, Structure::All, &view), [1]);
        assert_eq!(view.selected, Some((true, 16)));
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
                requested: Some((8, 4)),
                ..Default::default()
            },
        );
        state.bind("second");
        assert!(state.kind.is_none());
        assert!(state.views.is_empty());
    }
}
