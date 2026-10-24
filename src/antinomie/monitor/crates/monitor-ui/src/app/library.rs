// SPDX-License-Identifier: GPL-3.0-only
//! The Library: base images, detection rules and analysis tools. The sidebar
//! lists them; each opens as a page, a tab of the main area.
use super::*;
use crate::{
    widgets::{self, table, Tone},
    workspace::LibraryPage,
};

/// One installed base as its page row shows it.
struct BaseRow {
    id: String,
    name: String,
    status: RevisionStatus,
    /// What to do about a base that is not current; empty when it is.
    hint: String,
    size: u64,
    vms: usize,
    guest: String,
    details: String,
}

impl MonitorApp {
    /// Show `page` in the main area (focus it when it is open already).
    pub(super) fn open_library(&mut self, page: LibraryPage) {
        if !self.library_requests.contains(&page) {
            self.library_requests.push(page);
        }
    }

    /// The pages asked for since the last call; the workspace opens them.
    pub(crate) fn take_library_pages(&mut self) -> Vec<LibraryPage> {
        std::mem::take(&mut self.library_requests)
    }

    /// The sidebar's Library section: one row per page with its count.
    pub(super) fn library_sidebar(&mut self, ui: &mut egui::Ui) {
        library_header(ui, &mut self.settings.library_collapsed);
        if self.settings.library_collapsed {
            return;
        }
        let packs = self.rules_ui.pack_count();
        let rows = [
            (
                LibraryPage::BaseImages,
                egui_phosphor::regular::HARD_DRIVE,
                Some(self.snapshot.bases.len().to_string()),
            ),
            (
                LibraryPage::Rules,
                egui_phosphor::regular::SHIELD_CHECK,
                Some(match packs {
                    Some(1) => "1 pack".to_owned(),
                    Some(count) => format!("{count} packs"),
                    None => "…".to_owned(),
                }),
            ),
            (LibraryPage::Tools, egui_phosphor::regular::FLASK, None),
        ];
        for (page, icon, meta) in rows {
            if library_row(ui, icon, page.title(), meta.as_deref())
                .on_hover_text(match page {
                    LibraryPage::BaseImages => "Installed base images: open the page",
                    LibraryPage::Rules => "YARA, IDS and Sigma rule packs: open the page",
                    LibraryPage::Tools => "Optional static-analysis tools: open the page",
                })
                .clicked()
            {
                self.open_library(page);
            }
        }
    }

    /// The tab body of a Library page.
    pub(super) fn library_panel(&mut self, ui: &mut egui::Ui, page: LibraryPage) {
        match page {
            LibraryPage::BaseImages => self.bases_page(ui),
            LibraryPage::Rules => self.rules_page(ui),
            LibraryPage::Tools => self.analysis_tools_page(ui),
        }
    }

    fn analysis_tools_page(&mut self, ui: &mut egui::Ui) {
        if let Some(command) = crate::tools_page::show(
            ui,
            &self.snapshot.analysis_tools,
            self.snapshot.tool_install.as_ref(),
            !self.closing,
            self.routes.programs(),
        ) {
            self.send(command);
        }
    }

    fn rules_page(&mut self, ui: &mut egui::Ui) {
        let tools = antinomie_monitor_core::ruleset::ToolConfig::from_sigma_setting(
            &self.triage.detection_settings().effective_sigma_python(),
        );
        match self.rules_ui.page(
            ui,
            &self.options.data_dir,
            &mut self.settings.outbound_catalog,
            &tools,
            self.triage.detection_settings(),
        ) {
            Some(crate::rules_window::RulesAction::AppDependencies) => {
                self.dependencies.open = true;
            }
            Some(crate::rules_window::RulesAction::AnalysisTools) => {
                self.open_library(LibraryPage::Tools)
            }
            None => {}
        }
        // The triage view owns the live detection settings; keep the saved copy in step.
        self.settings.triage_detection = self.triage.detection_settings().clone();
        self.settings.triage_detection.rules_root.clear();
    }

    fn base_rows(&self) -> Vec<BaseRow> {
        self.snapshot
            .bases
            .iter()
            .map(|base| {
                let status =
                    RevisionStatus::of_base(base.revision, base.min_app_version.as_deref());
                let guest = base
                    .guest
                    .as_ref()
                    .map_or("Linux 6.12.94".to_string(), |guest| guest.id.clone());
                let hint = match status {
                    RevisionStatus::Current => String::new(),
                    RevisionStatus::NeedsNewerApp => "Needs a newer Antinomie".into(),
                    _ if newer_base(&self.snapshot, base).is_some() => {
                        "Outdated · newer base available".into()
                    }
                    _ => "Outdated · built for an earlier Antinomie".into(),
                };
                BaseRow {
                    id: base.id.clone(),
                    name: versioned_label(
                        &base.label,
                        base.revision,
                        base.min_app_version.as_deref(),
                    ),
                    status,
                    hint,
                    size: base.size_bytes,
                    vms: self
                        .snapshot
                        .vms
                        .iter()
                        .filter(|vm| vm.base_identity.as_deref() == Some(base.id.as_str()))
                        .count(),
                    guest,
                    details: describe_base(base),
                }
            })
            .collect()
    }

    /// The Base images page: the installed bases in a sortable table, the
    /// actions that add one, and what each base allows (right-click or the
    /// buttons under the table).
    fn bases_page(&mut self, ui: &mut egui::Ui) {
        let mut base_action: Option<(String, BaseAction)> = None;
        let mut clicked: Option<String> = None;
        let mut open_downloads = false;
        let stopped = self.snapshot.active_vm.is_none();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(stopped, egui::Button::new("Import base…"))
                .on_disabled_hover_text("Stop the running VM first")
                .clicked()
            {
                self.import_open = true;
            }
            if ui.button("Download base…").clicked() {
                open_downloads = true;
            }
            if ui.button("Build base…").clicked() {
                self.build_open = true;
            }
            if self.snapshot.bases_checking {
                theme::loading(ui, "Checking base images…").on_hover_text(
                    "The first start after an update or import checks each base once",
                );
            }
        });
        ui.add_space(4.0);
        let rows = self.base_rows();
        if rows.is_empty() && !self.snapshot.bases_checking {
            ui.label(RichText::new("No base images").color(theme::muted()));
            return self.finish_bases_page(base_action, clicked, open_downloads);
        }
        let font = self.settings.font_size;
        let order =
            crate::table_sort::order(ui.ctx(), "library_bases", rows.len(), |column, a, b| {
                let (a, b) = (&rows[a], &rows[b]);
                match column {
                    0 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    1 => a.hint.cmp(&b.hint),
                    2 => a.size.cmp(&b.size),
                    3 => a.vms.cmp(&b.vms),
                    _ => a.guest.to_lowercase().cmp(&b.guest.to_lowercase()),
                }
            });
        let selected = self.selected_base.clone();
        let height = (ui.available_height() - table::row_height(font) * 2.0).max(80.0);
        table::begin(ui);
        egui_extras::TableBuilder::new(ui)
            .id_salt("library_bases")
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .striped(true)
            .column(Column::remainder().at_least(220.0))
            .column(Column::initial(240.0).at_least(110.0).resizable(true))
            .column(Column::exact(88.0))
            .column(Column::exact(56.0))
            .column(Column::initial(120.0).at_least(80.0).resizable(true))
            .max_scroll_height(height)
            .min_scrolled_height(0.0)
            .header(table::header_height(font), |mut header| {
                for (column, title) in ["Base", "Status", "Size", "VMs", "Guest"]
                    .into_iter()
                    .enumerate()
                {
                    header.col(|ui| {
                        crate::table_sort::header_aligned(
                            ui,
                            "library_bases",
                            column,
                            title,
                            table::numeric_align(matches!(column, 2 | 3)),
                        )
                    });
                }
            })
            .body(|body| {
                body.rows(table::row_height(font), rows.len(), |mut row| {
                    let base = &rows[order[row.index()]];
                    let is_selected = selected.as_deref() == Some(base.id.as_str());
                    row.set_selected(is_selected);
                    row.col(|ui| {
                        table::row_mark(
                            ui,
                            if is_selected {
                                table::Mark::Selected
                            } else {
                                table::Mark::None
                            },
                        );
                        table::cell_click(ui, table::Cell::Text, &base.name)
                            .on_hover_text(format!("{}\n{}", base.name, base.details));
                    });
                    row.col(|ui| {
                        let (text, tone) = match base.status {
                            RevisionStatus::Current => ("Current", Tone::Good),
                            RevisionStatus::NeedsNewerApp => (base.hint.as_str(), Tone::Error),
                            _ => (base.hint.as_str(), Tone::Warn),
                        };
                        widgets::chip(ui, text, tone).on_hover_text(&base.details);
                    });
                    row.col(|ui| {
                        table::cell_click(
                            ui,
                            table::Cell::Number,
                            &format!("{:.1} GiB", base.size as f64 / 1073741824.0),
                        );
                    });
                    row.col(|ui| {
                        table::cell_click(ui, table::Cell::Number, &base.vms.to_string());
                    });
                    row.col(|ui| {
                        table::cell_click(ui, table::Cell::Text, &base.guest);
                    });
                    let response = row.response();
                    if response.clicked() || response.secondary_clicked() {
                        clicked = Some(base.id.clone());
                    }
                    response.context_menu(|ui| {
                        self.base_menu(ui, &base.id, &mut base_action);
                    });
                });
            });
        ui.add_space(6.0);
        let target = self.selected_base.clone().or(clicked.clone());
        ui.horizontal_wrapped(|ui| {
            let id = target
                .as_deref()
                .filter(|id| rows.iter().any(|row| row.id == *id));
            ui.add_enabled_ui(id.is_some(), |ui| {
                let id = id.unwrap_or_default().to_owned();
                if ui.button("New VM from this base…").clicked() {
                    base_action = Some((id.clone(), BaseAction::NewVm));
                }
                if ui.button("Open directory").clicked() {
                    base_action = Some((id.clone(), BaseAction::OpenDirectory));
                }
                if ui
                    .add_enabled(stopped, egui::Button::new("Delete base…"))
                    .on_disabled_hover_text("Stop the running VM first")
                    .clicked()
                {
                    base_action = Some((id, BaseAction::Delete));
                }
            });
            if id.is_none() {
                ui.weak("Select a base for its actions; right-click a row for the same menu.");
            }
        });
        if rows.iter().any(|row| row.status != RevisionStatus::Current) {
            ui.weak("Download base lists the bases made for this version of Antinomie.");
        }
        self.finish_bases_page(base_action, clicked, open_downloads);
    }

    fn base_menu(&self, ui: &mut egui::Ui, id: &str, action: &mut Option<(String, BaseAction)>) {
        if ui.button("New VM from this base…").clicked() {
            *action = Some((id.to_owned(), BaseAction::NewVm));
            ui.close_menu();
        }
        if ui.button("Open directory").clicked() {
            *action = Some((id.to_owned(), BaseAction::OpenDirectory));
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add_enabled(
                self.snapshot.active_vm.is_none(),
                egui::Button::new("Delete base…"),
            )
            .clicked()
        {
            *action = Some((id.to_owned(), BaseAction::Delete));
            ui.close_menu();
        }
    }

    fn finish_bases_page(
        &mut self,
        action: Option<(String, BaseAction)>,
        clicked: Option<String>,
        open_downloads: bool,
    ) {
        if open_downloads {
            self.open_downloads();
        }
        if let Some(identity) = clicked {
            self.selected_base = Some(identity);
        }
        if let Some((identity, action)) = action {
            match action {
                BaseAction::NewVm => self.new_image_from(identity),
                BaseAction::OpenDirectory => {
                    if let Some(base) = self.snapshot.bases.iter().find(|base| base.id == identity)
                    {
                        open_directory(&base.directory);
                    }
                }
                BaseAction::Delete => self.confirm = Some(Confirm::DeleteBase(identity)),
            }
        }
    }
}
