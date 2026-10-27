// SPDX-License-Identifier: GPL-3.0-only
//! The sample list: seven columns (name, description, tags, runs, parents /
//! children, latest run, short SHA-256), a search field, a tag filter that
//! keeps samples with every selected tag, and Roots only.
use super::{picker::TagPicker, *};
use crate::{
    sample_tags,
    widgets::{self, table, Tone},
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
fn started(ms: Option<u64>) -> String {
    ms.and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64))
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "Unavailable".into())
}

enum Action {
    Select(String),
    CopyHash(String),
    CopyName(String),
    EditTags(String, String, Vec<Tag>),
    Remove(String),
}

impl MonitorApp {
    pub(super) fn list_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let font = self.settings.font_size;
        let mut add = false;
        let mut verify = false;
        let mut download = false;
        let mut refresh = false;
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new("Samples")
                        .strong()
                        .color(theme::palette().heading),
                );
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
        if verify {
            self.samples_page.start_verify(&ctx, &self.options.data_dir);
        }
        if refresh {
            self.samples_page.refresh();
        }
        ui.add_space(4.0);
        let used: BTreeSet<Tag> = self
            .samples_page
            .rows
            .iter()
            .flat_map(|row| row.tags.iter().cloned())
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.samples_page.query)
                    .hint_text(theme::hint_text("Name, description, tag or SHA-256 prefix"))
                    .desired_width(300.0),
            );
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
        ui.horizontal(|ui| {
            ui.weak(format!("{} of {}", shown.len(), page.rows.len()));
            if let Some((message, failed)) = &page.notice {
                ui.colored_label(
                    if *failed {
                        theme::error()
                    } else {
                        theme::good()
                    },
                    message,
                );
            }
            if let Some(error) = &page.error {
                ui.colored_label(theme::error(), error);
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
        let height = ui.available_height().max(80.0);
        let mut action = None;
        table::begin(ui);
        TableBuilder::new(ui)
            .id_salt("library_samples")
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .striped(true)
            .column(Column::initial(180.0).at_least(110.0).resizable(true))
            .column(Column::remainder().at_least(140.0))
            .column(Column::initial(220.0).at_least(80.0).resizable(true))
            .column(Column::exact(56.0))
            .column(Column::exact(150.0))
            .column(Column::initial(200.0).at_least(120.0).resizable(true))
            .column(Column::exact(88.0))
            .max_scroll_height(height)
            .min_scrolled_height(0.0)
            .header(table::header_height(font), |mut header| {
                for (column, title) in [
                    "Name",
                    "Description",
                    "Tags",
                    "Runs",
                    "Parents / children",
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
                            table::numeric_align(matches!(column, 3 | 4)),
                        )
                    });
                }
            })
            .body(|body| {
                body.rows(
                    table::row_height(font) + 8.0,
                    shown.len(),
                    |mut table_row| {
                        let row = &page.rows[shown[order[table_row.index()]]];
                        let sha256 = row.record.sha256.as_str();
                        let selected = page.selected.as_deref() == Some(sha256);
                        table_row.set_selected(selected);
                        let problem = page.problems.get(sha256);
                        table_row.col(|ui| {
                            table::row_mark(
                                ui,
                                if problem.is_some() || !row.archived {
                                    table::Mark::Failed
                                } else if selected {
                                    table::Mark::Selected
                                } else {
                                    table::Mark::None
                                },
                            );
                            table::cell_rich(
                                ui,
                                table::Cell::Text,
                                RichText::new(&row.record.name).strong(),
                            );
                            if let Some(problem) = problem {
                                widgets::chip(ui, "✗ archive", Tone::Error).on_hover_text(problem);
                            } else if !row.archived {
                                widgets::chip(ui, "✗ missing", Tone::Error)
                                    .on_hover_text("The archive is not in the library folder");
                            }
                        });
                        table_row.col(|ui| {
                            if row.record.description.is_empty() {
                                ui.label(theme::hint_text("-"));
                            } else {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&row.record.description)
                                            .color(theme::muted()),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(&row.record.description);
                            }
                        });
                        table_row.col(|ui| sample_tags::short(ui, &row.tags));
                        table_row.col(|ui| {
                            table::cell(ui, table::Cell::Number, &row.runs.count.to_string());
                        });
                        table_row.col(|ui| {
                            let count = |n: usize| {
                                if n == 0 {
                                    "–".to_owned()
                                } else {
                                    n.to_string()
                                }
                            };
                            table::cell(
                                ui,
                                table::Cell::Number,
                                &format!("{} / {}", count(row.parents), count(row.children)),
                            )
                            .on_hover_text(format!(
                                "{} parents · {} children",
                                row.parents, row.children
                            ));
                        });
                        table_row.col(|ui| match &row.runs.latest {
                            Some(run) => {
                                table::cell(ui, table::Cell::Mono, &started(run.started_ms));
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
                            table::cell(ui, table::Cell::Mono, &sha256[..SHORT_HASH])
                                .on_hover_text(sha256);
                        });
                        let response = table_row.response();
                        if response.clicked() || response.secondary_clicked() {
                            action = Some(Action::Select(sha256.to_owned()));
                        }
                        response.context_menu(|ui| {
                            if ui.button("Edit tags…").clicked() {
                                action = Some(Action::EditTags(
                                    sha256.to_owned(),
                                    row.record.name.clone(),
                                    row.tags.clone(),
                                ));
                                ui.close_menu();
                            }
                            if ui.button("Copy SHA-256").clicked() {
                                action = Some(Action::CopyHash(sha256.to_owned()));
                                ui.close_menu();
                            }
                            if ui.button("Copy name").clicked() {
                                action = Some(Action::CopyName(row.record.name.clone()));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Remove…").clicked() {
                                action = Some(Action::Remove(sha256.to_owned()));
                                ui.close_menu();
                            }
                        });
                    },
                );
            });
        match action {
            Some(Action::Select(sha256)) => self.samples_page.selected = Some(sha256),
            Some(Action::CopyHash(text) | Action::CopyName(text)) => ctx.copy_text(text),
            Some(Action::EditTags(sha256, name, tags)) => {
                self.samples_page.editing = Some((sha256, name, TagPicker::with(&tags)));
            }
            Some(Action::Remove(sha256)) => self.samples_page.confirm_remove = Some(sha256),
            None => {}
        }
    }
}
