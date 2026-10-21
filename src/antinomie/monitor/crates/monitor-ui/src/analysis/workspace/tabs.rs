// SPDX-License-Identifier: MIT
//! The tab strip across the top of the static analysis window and the view
//! each tab shows. A tab maps onto one retained analysis category, except
//! File Info and Content, which draw on several.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::analysis) enum Tab {
    #[default]
    FileInfo,
    Content,
    Strings,
    Binwalk,
    Yara,
    Capa,
    Disassembly,
    Decompilation,
    Symbols,
}

impl Tab {
    pub(super) const ALL: [Self; 9] = [
        Self::FileInfo,
        Self::Content,
        Self::Strings,
        Self::Binwalk,
        Self::Yara,
        Self::Capa,
        Self::Disassembly,
        Self::Decompilation,
        Self::Symbols,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::FileInfo => "File Info",
            Self::Content => "Content",
            Self::Strings => "Strings",
            Self::Binwalk => "Binwalk",
            Self::Yara => "YARA",
            Self::Capa => "Capa Matrix",
            Self::Disassembly => "Disassembly",
            Self::Decompilation => "Decompilation",
            Self::Symbols => "Symbols",
        }
    }

    /// The category a tab shows; None for the tabs that combine several.
    fn kind(self) -> Option<AnalysisKind> {
        Some(match self {
            Self::FileInfo | Self::Content => return None,
            Self::Strings => AnalysisKind::Strings,
            Self::Binwalk => AnalysisKind::Embedded,
            Self::Yara => AnalysisKind::Rules,
            Self::Capa => AnalysisKind::Capabilities,
            Self::Disassembly => AnalysisKind::Disassembly,
            Self::Decompilation => AnalysisKind::Decompilation,
            Self::Symbols => AnalysisKind::Structures,
        })
    }
}

/// The views inside File Info.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::analysis) enum FileInfo {
    #[default]
    Summary,
    Headers,
    Sections,
    Segments,
    Hardening,
    Identification,
    Entropy,
}

impl FileInfo {
    const ALL: [Self; 7] = [
        Self::Summary,
        Self::Headers,
        Self::Sections,
        Self::Segments,
        Self::Hardening,
        Self::Identification,
        Self::Entropy,
    ];

    fn target(self) -> Option<(AnalysisKind, Structure)> {
        Some(match self {
            Self::Summary => return None,
            Self::Headers => (AnalysisKind::Structures, Structure::Headers),
            Self::Sections => (AnalysisKind::Structures, Structure::Sections),
            Self::Segments => (AnalysisKind::Structures, Structure::Segments),
            Self::Hardening => (AnalysisKind::Hardening, Structure::All),
            Self::Identification => (AnalysisKind::Identification, Structure::All),
            Self::Entropy => (AnalysisKind::Entropy, Structure::All),
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Headers => "Headers",
            Self::Sections => "Sections",
            Self::Segments => "Segments",
            Self::Hardening => "Hardening",
            Self::Identification => "Identification",
            Self::Entropy => "Entropy",
        }
    }
}

/// The tab, and File Info view, that shows `kind`.
pub(super) fn locate(kind: AnalysisKind, current: FileInfo) -> (Tab, FileInfo) {
    let info = |view| (Tab::FileInfo, view);
    match kind {
        AnalysisKind::Metadata => info(FileInfo::Summary),
        AnalysisKind::Hardening => info(FileInfo::Hardening),
        AnalysisKind::Identification => info(FileInfo::Identification),
        AnalysisKind::Entropy => info(FileInfo::Entropy),
        AnalysisKind::Structures => info(FileInfo::Sections),
        kind => (
            Tab::ALL
                .into_iter()
                .find(|tab| tab.kind() == Some(kind))
                .unwrap_or_default(),
            current,
        ),
    }
}

pub(super) fn show(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
    listing: Option<&Result<AnalysisListingPage, String>>,
) -> Option<ReportAction> {
    let mut action = header(ui, report, state);
    ui.add_space(4.0);
    crate::widgets::tab_row(ui, |ui| {
        for tab in Tab::ALL {
            let section = tab
                .kind()
                .and_then(|kind| report.sections.iter().find(|section| section.kind == kind));
            let pending = tab.kind().is_some_and(|kind| pending(report, kind));
            let title = if pending {
                format!(
                    "{} {}",
                    egui_phosphor::regular::HOURGLASS_MEDIUM,
                    tab.label()
                )
            } else {
                tab.label().to_owned()
            };
            let mut item = crate::widgets::TabItem::new(title);
            if tab.kind().is_some() && section.is_none() {
                item = item.disabled(super::NOT_REQUESTED);
            } else if let Some(rows) = section.and_then(|section| counted(tab, section)) {
                item = item.badge(rows.to_string(), crate::widgets::Tone::Neutral);
            }
            if crate::widgets::tab(ui, state.tab == tab, &item).clicked() {
                state.tab = tab;
            }
        }
    });
    ui.separator();
    if state.tab != Tab::Content {
        state.content.leave();
    }
    let next = match state.tab {
        Tab::FileInfo => file_info(ui, report, state, listing),
        Tab::Content => content::show(ui, report, &mut state.content, preview),
        Tab::Symbols => {
            if !matches!(
                state.symbols,
                Structure::Symbols | Structure::Imports | Structure::Exports
            ) {
                state.symbols = Structure::Symbols;
            }
            crate::widgets::tabs(
                ui,
                [Structure::Symbols, Structure::Imports, Structure::Exports]
                    .map(|filter| (filter, filter.label().into())),
                &mut state.symbols,
            );
            let filter = state.symbols;
            category(ui, report, state, listing, AnalysisKind::Structures, filter)
        }
        Tab::Capa => {
            let section = report
                .sections
                .iter()
                .find(|section| section.kind == AnalysisKind::Capabilities);
            match section {
                Some(section) if !section.entries.is_empty() && !state.capa.table => {
                    capa_matrix::show(ui, section, &mut state.capa);
                    None
                }
                _ => {
                    if section.is_some_and(|section| !section.entries.is_empty()) {
                        capa_matrix::toggle(ui, &mut state.capa);
                    }
                    category(
                        ui,
                        report,
                        state,
                        listing,
                        AnalysisKind::Capabilities,
                        Structure::All,
                    )
                }
            }
        }
        tab => {
            let kind = tab.kind().expect("a single-category tab");
            category(ui, report, state, listing, kind, Structure::All)
        }
    };
    action = action.or(next);
    action
}

/// The file's name, size and SHA-256, the tools that act on the whole
/// report, and the offset of the selected row when Content can show it.
fn header(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
) -> Option<ReportAction> {
    let mut action = None;
    ui.horizontal_wrapped(|ui| {
        ui.strong(file_name(report, state));
        if let Some(len) = report.specimen_len {
            ui.label(crate::values::file_size(len));
        }
        if let Some(hash) = &report.specimen_sha256 {
            ui.monospace(format!("SHA-256 {}…", &hash[..hash.len().min(16)]))
                .on_hover_text(hash);
            if ui
                .small_button(egui_phosphor::regular::COPY)
                .on_hover_text("Copy SHA-256")
                .clicked()
            {
                ui.ctx().copy_text(hash.clone());
            }
        }
        if let Some(offset) = selected_offset(report, state) {
            if ui
                .button(format!(
                    "{} Show 0x{offset:x} in Content",
                    egui_phosphor::regular::FILE_MAGNIFYING_GLASS
                ))
                .on_hover_text("Open the file content at the selected row's offset")
                .clicked()
            {
                state.content.go_to(offset);
                state.tab = Tab::Content;
            }
        }
        action = export_controls(ui, report, None, true);
    });
    action
}

fn file_info(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    listing: Option<&Result<AnalysisListingPage, String>>,
) -> Option<ReportAction> {
    let items = FileInfo::ALL.map(|view| {
        let title = match view.target() {
            Some((kind, _)) if pending(report, kind) => {
                format!(
                    "{} {}",
                    egui_phosphor::regular::HOURGLASS_MEDIUM,
                    view.label()
                )
            }
            _ => view.label().to_owned(),
        };
        let mut item = crate::widgets::TabItem::new(title);
        if view
            .target()
            .is_some_and(|(kind, _)| !report.sections.iter().any(|section| section.kind == kind))
        {
            item = item.disabled(super::NOT_REQUESTED);
        }
        (view, item)
    });
    egui::ScrollArea::horizontal()
        .id_salt("file-info-views")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            crate::widgets::segmented(ui, items, &mut state.file_info);
        });
    ui.add_space(4.0);
    match state.file_info.target() {
        None => {
            state.kind = None;
            state.active_view = None;
            overview(ui, report, state)
        }
        Some((kind, filter)) => category(ui, report, state, listing, kind, filter),
    }
}

/// One category's results, or why this report has none.
fn category(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    listing: Option<&Result<AnalysisListingPage, String>>,
    kind: AnalysisKind,
    filter: Structure,
) -> Option<ReportAction> {
    state.kind = Some(kind);
    state.structure = filter;
    if !report.sections.iter().any(|section| section.kind == kind) {
        state.active_view = None;
        ui.add(
            egui::Label::new(format!(
                "{} was not part of this analysis. Start a new static analysis with it selected.",
                kind.label()
            ))
            .wrap(),
        );
        return None;
    }
    results(ui, report, state, listing, None)
}

/// The row count a tab shows as its badge: the categories that list findings.
fn counted(tab: Tab, section: &AnalysisSection) -> Option<u64> {
    if !matches!(tab, Tab::Strings | Tab::Binwalk | Tab::Yara | Tab::Capa) {
        return None;
    }
    let rows = section
        .listing
        .as_ref()
        .map_or(section.entries.len() as u64, |listing| listing.rows);
    (rows > 0).then_some(rows)
}

fn pending(report: &AnalysisReport, kind: AnalysisKind) -> bool {
    super::super::in_progress(report)
        && report.sections.iter().any(|section| {
            section.kind == kind
                && section.state == antinomie_monitor_core::AnalysisSectionState::Pending
        })
}

/// The file offset of the selected row in the visible category, when the
/// row records one.
fn selected_offset(report: &AnalysisReport, state: &WorkspaceState) -> Option<u64> {
    if state.tab == Tab::Content {
        return None;
    }
    records::file_offset(selected_row(report, state, None)?, report.specimen_len)
}

/// The row selected in the visible category (`forced` for a separate pane).
pub(in crate::analysis) fn selected_row<'a>(
    report: &'a AnalysisReport,
    state: &'a WorkspaceState,
    forced: Option<AnalysisKind>,
) -> Option<&'a AnalysisEntry> {
    let kind = forced.or(state.kind)?;
    let view = state.views.get(state.active_view.as_ref()?)?;
    match &view.listing.selected {
        Some((_, entry)) => Some(entry),
        None => {
            let section = report
                .sections
                .iter()
                .find(|section| section.kind == kind)?;
            selected_entry(section, view)
        }
    }
}
