// SPDX-License-Identifier: GPL-3.0-only
//! The sample list: seven columns (name, description, tags, runs, parents /
//! children, latest run, short SHA-256), a search field, a tag filter that
//! keeps samples with every selected tag, and Roots only.
use super::{picker::TagPicker, *};
use crate::{
    sample_tags,
    widgets::{self, fit_table, Tone},
};
use antinomie_monitor_core::samples::TagKind;

/// The first hex digits of a SHA-256 the list shows.
const SHORT_HASH: usize = 8;

impl Row {
    /// The row matches the search text: name, description, a tag or the start
    /// of the SHA-256.
    fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        query.is_empty()
            || self.record.name.to_lowercase().contains(&query)
            || self.record.description.to_lowercase().contains(&query)
            || self.record.sha256.starts_with(&query)
            || self
                .tags
                .iter()
                .any(|tag| sample_tags::text(tag).to_lowercase().contains(&query))
    }
}

/// The latest run's start as the list writes it.
pub(in crate::app::samples_page) fn started(ms: Option<u64>) -> String {
    ms.and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64))
        .map(|time| {
            crate::time_format::zoned(time)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "Unavailable".into())
}

enum Action {
    Select(String),
    Open(String),
    Notes(String),
    CopyHash(String),
    CopyName(String),
    EditTags(String, String, Vec<Tag>),
    EditText(String, String, String),
    Report(String, String),
    Remove(String),
}

impl MonitorApp {
    pub(super) fn list_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let font = self.settings.font_size;
        self.list_toolbar(ui);
        ui.add_space(4.0);
        self.list_filters(ui);
        let page = &self.samples_page;
        let shown: Vec<usize> = page
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.matches(&page.query)
                    && (!page.roots_only || row.parents == 0)
                    && page.tag_filter.iter().all(|tag| row.tags.contains(tag))
            })
            .map(|(index, _)| index)
            .collect();
        let mut cleared = false;
        ui.horizontal(|ui| {
            ui.weak(format!("{} of {}", shown.len(), page.rows.len()));
            if let Some((message, failed)) = &page.notice {
                cleared = if *failed {
                    crate::activity::status(ui, crate::activity::Level::Error, message, None)
                } else {
                    crate::activity::success(ui, message, None)
                };
            }
            if let Some(error) = &page.error {
                crate::activity::error(ui, error);
            }
        });
        ui.add_space(2.0);
        if shown.is_empty() {
            ui.add_space(8.0);
            ui.label(
                RichText::new(if page.rows.is_empty() && page.loaded {
                    "No samples yet. Add a file or download one."
                } else if page.loaded {
                    "No sample matches."
                } else {
                    "Reading the library…"
                })
                .color(theme::muted()),
            );
            return;
        }
        let order =
            crate::table_sort::order(&ctx, "library_samples", shown.len(), |column, a, b| {
                let (a, b) = (&page.rows[shown[a]], &page.rows[shown[b]]);
                match column {
                    0 => a
                        .record
                        .name
                        .to_lowercase()
                        .cmp(&b.record.name.to_lowercase()),
                    1 => a
                        .record
                        .description
                        .to_lowercase()
                        .cmp(&b.record.description.to_lowercase()),
                    2 => a.tags.len().cmp(&b.tags.len()),
                    3 => a.runs.count.cmp(&b.runs.count),
                    4 => (a.parents, a.children).cmp(&(b.parents, b.children)),
                    5 => a
                        .runs
                        .latest
                        .as_ref()
                        .and_then(|run| run.started_ms)
                        .cmp(&b.runs.latest.as_ref().and_then(|run| run.started_ms)),
                    _ => a.record.sha256.cmp(&b.record.sha256),
                }
            });
        let action = self.library_table(ui, &shown, &order, font);
        if cleared {
            self.samples_page.notice = None;
        }
        match action {
            Some(Action::Select(sha256)) => self.samples_page.selected = Some(sha256),
            Some(Action::Open(sha256)) => {
                self.samples_page.selected = Some(sha256.clone());
                self.samples_page.open_detail(&sha256);
            }
            Some(Action::Notes(sha256)) => {
                self.samples_page.selected = Some(sha256.clone());
                self.samples_page.open_notes(&sha256);
            }
            Some(Action::CopyHash(text) | Action::CopyName(text)) => ctx.copy_text(text),
            Some(Action::EditTags(sha256, name, tags)) => {
                self.samples_page.editing = Some((sha256, name, TagPicker::with(&tags)));
            }
            Some(Action::EditText(sha256, name, description)) => {
                self.samples_page.edit_text_of(&sha256, &name, &description)
            }
            Some(Action::Report(sha256, name)) => self.samples_page.report.open(&sha256, &name),
            Some(Action::Remove(sha256)) => self.samples_page.confirm_remove = Some(sha256),
            None => {}
        }
    }

    /// The buttons over the list: add, download, custody log, verify and refresh.
    fn list_toolbar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut add = false;
        let mut verify = false;
        let mut download = false;
        let mut custody = false;
        let mut refresh = false;
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(theme::section_title(ui, "Samples"));
                if self.samples_page.loading.is_some() {
                    theme::spinner(ui);
                }
            },
            |ui| {
                add = ui.button("Add file…").clicked();
                download = ui
                    .button("Download…")
                    .on_hover_text("Search MalwareBazaar and MalShare; downloads land here")
                    .clicked();
                custody = ui
                    .button("Custody log")
                    .on_hover_text("What happened to every sample, with the hash chain checked")
                    .clicked();
                verify = ui
                    .add_enabled(
                        self.samples_page.verifying.is_none(),
                        egui::Button::new("Verify all"),
                    )
                    .on_hover_text("Read every archive back and compare its SHA-256")
                    .clicked();
                refresh = ui
                    .button(egui_phosphor::regular::ARROW_CLOCKWISE)
                    .on_hover_text("Read the library and the runs again")
                    .clicked();
            },
        );
        if add {
            self.samples_page.open_add(None);
        }
        if download {
            self.samples.open = true;
        }
        if custody {
            self.samples_page.custody_all = Some(super::custody_all::CustodyAll::new());
        }
        if verify {
            self.samples_page.start_verify(&ctx, &self.options.data_dir);
        }
        if refresh {
            self.samples_page.refresh();
        }
    }

    /// The search row and the tag filter.
    fn list_filters(&mut self, ui: &mut egui::Ui) {
        let used: BTreeSet<Tag> = self
            .samples_page
            .rows
            .iter()
            .flat_map(|row| row.tags.iter().cloned())
            .collect();
        ui.horizontal_wrapped(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.samples_page.query)
                    .hint_text(crate::theme::placeholder(
                        ui,
                        "Name, description, tag or SHA-256 prefix",
                    ))
                    .margin(crate::widgets::clear_margin(egui::Margin::symmetric(4, 2)))
                    .desired_width(crate::theme::plain_edit_width(380.0)),
            );
            crate::widgets::clear_button(ui, &edit, &mut self.samples_page.query);
            let count = self.samples_page.tag_filter.len();
            if ui
                .selectable_label(
                    self.samples_page.tags_open,
                    if count == 0 {
                        "Tags ▾".to_owned()
                    } else {
                        format!("Tags ({count}) ▾")
                    },
                )
                .on_hover_text("Samples that have every selected tag")
                .clicked()
            {
                self.samples_page.tags_open = !self.samples_page.tags_open;
            }
            for tag in self.samples_page.tag_filter.clone() {
                sample_tags::tag(ui, &tag);
            }
            if count > 0 && widgets::link(ui, "Clear").clicked() {
                self.samples_page.tag_filter.clear();
            }
            if widgets::toggle_chip(ui, "Roots only", self.samples_page.roots_only, None)
                .on_hover_text("Samples with no known parent")
                .clicked()
            {
                self.samples_page.roots_only = !self.samples_page.roots_only;
            }
        });
        if self.samples_page.tags_open {
            egui::Frame::new()
                .fill(theme::palette().panel)
                .inner_margin(8)
                .corner_radius(6)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for (kind, title) in [
                        (TagKind::Verdict, "Verdict"),
                        (TagKind::Category, "Malware category"),
                        (TagKind::Technique, "ATT&CK technique"),
                        (TagKind::Custom, "Custom"),
                    ] {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let (rect, _) = ui
                                .allocate_exact_size(egui::vec2(120.0, 18.0), egui::Sense::hover());
                            ui.painter().text(
                                rect.left_center(),
                                egui::Align2::LEFT_CENTER,
                                title,
                                egui::FontId::proportional(11.0),
                                theme::muted(),
                            );
                            let tags: Vec<&Tag> =
                                used.iter().filter(|tag| tag.kind == kind).collect();
                            if tags.is_empty() {
                                ui.label(theme::hint_text("none yet"));
                            }
                            for tag in tags {
                                let on = self.samples_page.tag_filter.contains(tag);
                                let shown = sample_tags::tag(ui, tag);
                                let response = ui
                                    .interact(
                                        shown.rect,
                                        shown.id.with("filter"),
                                        egui::Sense::click(),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                if on {
                                    ui.painter().rect_stroke(
                                        shown.rect.expand(2.0),
                                        8.0,
                                        egui::Stroke::new(1.5_f32, theme::palette().accent),
                                        egui::StrokeKind::Outside,
                                    );
                                }
                                if response.clicked() {
                                    if on {
                                        self.samples_page.tag_filter.remove(tag);
                                    } else {
                                        self.samples_page.tag_filter.insert(tag.clone());
                                    }
                                }
                            }
                        });
                    }
                });
        }
    }

    /// The table of the samples that are shown, in the order the header asks for.
    fn library_table(
        &self,
        ui: &mut egui::Ui,
        shown: &[usize],
        order: &[usize],
        font: f32,
    ) -> Option<Action> {
        let page = &self.samples_page;
        let height = ui.available_height().max(80.0);
        let mut action = None;
        ui.scope(|ui| {
            // Not selectable: a click on the text of any cell reaches the row.
            ui.style_mut().interaction.selectable_labels = false;
            FitBuilder::new(ui)
                .id_salt("library_samples")
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .column(Col::flex(140.0).at_least(110.0).resizable(true))
                .column(Col::rest(80.0).at_least(120.0))
                .column(Col::flex(230.0).at_least(80.0).resizable(true))
                .column(Col::fixed(72.0))
                .column(Col::fixed(100.0))
                .column(Col::flex(250.0).at_least(120.0).resizable(true))
                .column(Col::fixed(104.0))
                .max_scroll_height(height)
                .min_scrolled_height(0.0)
                .header(fit_table::header_height(font), |mut header| {
                    for (column, title) in [
                        "Name",
                        "Description",
                        "Tags",
                        "Runs",
                        "Lineage",
                        "Latest run",
                        "SHA-256",
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        header.col(|ui| {
                            crate::table_sort::header_aligned(
                                ui,
                                "library_samples",
                                column,
                                title,
                                fit_table::numeric_align(matches!(column, 3 | 4)),
                            )
                        });
                    }
                })
                .body(|body| {
                    body.rows(
                        fit_table::list_row_height(font),
                        shown.len(),
                        |mut table_row| {
                            let row = &page.rows[shown[order[table_row.index()]]];
                            let sha256 = row.record.sha256.as_str();
                            let selected = page.selected.as_deref() == Some(sha256);
                            table_row.set_selected(selected);
                            let problem = page.problems.get(sha256);
                            sample_cells(&mut table_row, row, problem, selected);
                            let response = table_row.response();
                            if response.double_clicked() {
                                action = Some(Action::Open(sha256.to_owned()));
                            } else if response.clicked() || response.secondary_clicked() {
                                action = Some(Action::Select(sha256.to_owned()));
                            }
                            sample_menu(&response, sha256, row, &mut action);
                        },
                    );
                });
        });
        action
    }
}

/// The cells of a sample's row.
fn sample_cells(
    table_row: &mut egui_extras::TableRow<'_, '_>,
    row: &Row,
    problem: Option<&String>,
    selected: bool,
) {
    let sha256 = row.record.sha256.as_str();
    table_row.col(|ui| {
        fit_table::row_mark(
            ui,
            if problem.is_some() || !row.archived || !row.custody_ok {
                fit_table::Mark::Failed
            } else if selected {
                fit_table::Mark::Selected
            } else {
                fit_table::Mark::None
            },
        );
        fit_table::cell_rich(
            ui,
            fit_table::Cell::Text,
            RichText::new(&row.record.name).strong(),
        );
        if let Some(problem) = problem {
            widgets::chip(ui, "✗ archive", Tone::Error).on_hover_text(problem);
        } else if !row.archived {
            widgets::chip(ui, "✗ missing", Tone::Error)
                .on_hover_text("The archive is not in the library folder");
        }
        if !row.custody_ok {
            widgets::chip(ui, "✗ custody", Tone::Error).on_hover_text(
                "The custody log does not verify. Open the sample's Custody log tab.",
            );
        }
    });
    table_row.col(|ui| {
        if row.record.description.is_empty() {
            ui.label(theme::hint_text("-"));
        } else {
            ui.add(
                egui::Label::new(RichText::new(&row.record.description).color(theme::muted()))
                    .truncate(),
            )
            .on_hover_text(&row.record.description);
        }
    });
    table_row.col(|ui| sample_tags::short(ui, &row.tags));
    table_row.col(|ui| {
        fit_table::cell(ui, fit_table::Cell::Number, &row.runs.count.to_string());
    });
    table_row.col(|ui| {
        let count = |n: usize| {
            if n == 0 {
                "–".to_owned()
            } else {
                n.to_string()
            }
        };
        fit_table::cell(
            ui,
            fit_table::Cell::Number,
            &format!("{} / {}", count(row.parents), count(row.children)),
        )
        .on_hover_text(format!(
            "{} parents · {} children",
            row.parents, row.children
        ));
    });
    table_row.col(|ui| match &row.runs.latest {
        Some(run) => {
            fit_table::cell(ui, fit_table::Cell::Mono, &started(run.started_ms))
                .on_hover_text(crate::time_format::unix_ms(run.started_ms));
            widgets::chip(
                ui,
                &run.exit,
                match run.exit.as_str() {
                    "Exit 0" => Tone::Good,
                    "Running" => Tone::Live,
                    _ => Tone::Warn,
                },
            )
            .on_hover_text(format!("{} · run {}", run.vm_name, run.run_id));
        }
        None => {
            ui.label(theme::hint_text("never run"));
        }
    });
    table_row.col(|ui| {
        fit_table::cell(ui, fit_table::Cell::Mono, &sha256[..SHORT_HASH]).on_hover_text(sha256);
    });
}

/// The menu of a sample's row.
fn sample_menu(response: &egui::Response, sha256: &str, row: &Row, action: &mut Option<Action>) {
    response.context_menu(|ui| {
        if ui.button("Open").clicked() {
            *action = Some(Action::Open(sha256.to_owned()));
            ui.close();
        }
        if ui.button("Notes…").clicked() {
            *action = Some(Action::Notes(sha256.to_owned()));
            ui.close();
        }
        if ui.button("Edit tags…").clicked() {
            *action = Some(Action::EditTags(
                sha256.to_owned(),
                row.record.name.clone(),
                row.tags.clone(),
            ));
            ui.close();
        }
        if ui.button("Edit name and description…").clicked() {
            *action = Some(Action::EditText(
                sha256.to_owned(),
                row.record.name.clone(),
                row.record.description.clone(),
            ));
            ui.close();
        }
        if ui.button("Export report…").clicked() {
            *action = Some(Action::Report(sha256.to_owned(), row.record.name.clone()));
            ui.close();
        }
        if ui.button("Copy SHA-256").clicked() {
            *action = Some(Action::CopyHash(sha256.to_owned()));
            ui.close();
        }
        if ui.button("Copy name").clicked() {
            *action = Some(Action::CopyName(row.record.name.clone()));
            ui.close();
        }
        ui.separator();
        if ui.button("Remove…").clicked() {
            *action = Some(Action::Remove(sha256.to_owned()));
            ui.close();
        }
    });
}
