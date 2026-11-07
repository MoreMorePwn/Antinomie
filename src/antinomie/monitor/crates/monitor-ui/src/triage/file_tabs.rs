// SPDX-License-Identifier: GPL-3.0-only
//! The File activity section: its tabs, filters and tables. The tab model and
//! the rows' sink are in `antinomie_triage::file_tabs`.
use super::file_category::EVENT_HEADERS;
use super::*;

pub(super) use antinomie_triage::file_tabs::*;

impl TriageView {
    /// The visibility toggles of the filter bar. Hide stdio and Hide library
    /// start on, and so does Failed attempts.
    pub(super) fn file_toggles(&mut self, ui: &mut egui::Ui) {
        use crate::widgets::toggle_chip;
        // Failed attempts per table; a call counts once in each table it is in.
        let per_tab: Vec<(&str, u64)> = self.scan.as_ref().map_or_else(Vec::new, |scan| {
            FileTab::ALL
                .into_iter()
                .map(|tab| {
                    (
                        tab.title(),
                        scan.counts.visibility[file_visibility::visibility_slot(tab)].failed,
                    )
                })
                .collect()
        });
        let failed: u64 = per_tab.iter().map(|(_, count)| count).sum();
        let tab = if self.history_tab || self.by_file {
            None
        } else {
            Some(self.files)
        };
        let count = tab.map_or_else(Default::default, |tab| {
            self.scan.as_ref().map_or_else(Default::default, |scan| {
                scan.counts.visibility[file_visibility::visibility_slot(tab)]
            })
        });
        let counted = self.scan.is_some();
        let label = |name: &str, hidden: u64| {
            if counted {
                format!("{name} ({hidden})")
            } else {
                name.to_owned()
            }
        };
        let visibility = &mut self.scan_request.file_visibility;
        let mut changed = false;
        if toggle_chip(
            ui,
            &label("Hide stdio", count.stdio),
            visibility.hide_standard_io,
            None,
        )
        .on_hover_text(format!(
            "Hide stdin, stdout, stderr. {} rows in this table are standard input/output.",
            count.stdio
        ))
        .clicked()
        {
            visibility.hide_standard_io = !visibility.hide_standard_io;
            changed = true;
        }
        if toggle_chip(
            ui,
            &label("Hide library", count.library),
            visibility.hide_libraries,
            None,
        )
        .on_hover_text(format!(
            "Hide shared libraries and the loader cache. {} rows in this table are libraries.",
            count.library
        ))
        .clicked()
        {
            visibility.hide_libraries = !visibility.hide_libraries;
            changed = true;
        }
        let failed_here = if tab.is_some() { count.failed } else { failed };
        let breakdown = per_tab
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(title, count)| format!("{title} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut hover = if tab.is_some() {
            format!("{failed_here} failed attempts in this tab; {failed} in this run")
        } else {
            format!("{failed} failed attempts in this run")
        };
        if !breakdown.is_empty() {
            hover.push_str(&format!(" ({breakdown})"));
        }
        hover.push_str(
            ". Calls the kernel refused, with their result; turn this off to hide them. They do not count as changes.",
        );
        let failed_label = if counted {
            format!("Failed attempts ({failed_here})")
        } else {
            "Failed attempts".to_owned()
        };
        if toggle_chip(ui, &failed_label, visibility.show_failed, None)
            .on_hover_text(hover)
            .clicked()
        {
            visibility.show_failed = !visibility.show_failed;
            changed = true;
        }
        if counted && count.total > 0 {
            let group = antinomie_monitor_core::analysis::detection::group_digits;
            let (hide_stdio, hide_library) = (
                self.scan_request.file_visibility.hide_standard_io,
                self.scan_request.file_visibility.hide_libraries,
            );
            if count.shown == count.total {
                ui.colored_label(theme::muted(), format!("{} rows", group(count.total)));
            } else {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "{} of {} rows shown",
                        group(count.shown),
                        group(count.total)
                    ),
                );
            }
            if (hide_stdio && count.stdio > 0 || hide_library && count.library > 0)
                && ui
                    .small_button("Show all")
                    .on_hover_text("Turn the Hide chips off to list every row")
                    .clicked()
            {
                self.scan_request.file_visibility.hide_standard_io = false;
                self.scan_request.file_visibility.hide_libraries = false;
                changed = true;
            }
        }
        if changed {
            for index in file_slots() {
                self.scan_request.offsets[index] = 0;
            }
            self.request_query_refresh();
        }
    }

    pub(super) fn files(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        // A row menu of a Files tab asked for a file's reconstruction.
        let asked = ui.ctx().data_mut(|data| {
            data.remove_temp::<String>(egui::Id::new(file_activity::RECONSTRUCT_REQUEST))
        });
        if let Some(path) = asked {
            self.file_history.reconstruct(&path);
            self.history_tab = true;
            self.by_file = false;
        }
        // A row menu asked for the file's history.
        let shown = ui.ctx().data_mut(|data| {
            data.remove_temp::<String>(egui::Id::new(file_activity::HISTORY_REQUEST))
        });
        if let Some(path) = shown {
            self.file_history.open_on(&path);
            self.history_tab = true;
            self.by_file = false;
        }
        self.file_tabs(ui);
        if self.by_file && !self.history_tab {
            let activity = self.scan.as_ref().map(|scan| scan.file_activity.clone());
            let clock = self.scan.as_ref().and_then(|scan| scan.clock_anchor);
            let (start, flagged) = self
                .scan
                .as_ref()
                .map_or((None, Default::default()), |scan| {
                    (run_start(scan), scan.flagged_paths.clone())
                });
            self.file_history.overview(
                ui,
                activity.as_deref(),
                &file_shown::Notes {
                    start,
                    flagged: &flagged,
                },
                clock.or(input.clock_anchor),
            );
            return;
        }
        if self.history_tab {
            let activity = self.scan.as_ref().map(|scan| scan.file_activity.clone());
            let clock = self.scan.as_ref().and_then(|scan| scan.clock_anchor);
            // Where the window notes an export in the sample's custody log.
            if let Some(data_dir) = self.scan_request.data_dir.clone() {
                ui.ctx().data_mut(|data| {
                    data.insert_temp(egui::Id::new(file_activity::RECONSTRUCT_DATA_DIR), data_dir)
                });
            }
            self.file_history.show(
                ui,
                activity.as_deref(),
                clock.or(input.clock_anchor),
                self.details_directory.as_deref(),
            );
            return;
        }
        let tab = self.files;
        let index = tab.slot();
        let (retained, total) = self.scan.as_ref().map_or((0, 0), |scan| {
            let (rows, omitted) = scan.file_rows(tab);
            (rows, rows as u64 + omitted)
        });
        self.query_bar(
            ui,
            index,
            FILE_FIELDS,
            tab.example(),
            (retained, total),
            Bar::Files,
        );
        let Some(scan) = &self.scan else {
            theme::loading_weak(ui, "Indexing this run’s files…");
            return;
        };
        let clock = scan.clock_anchor.or(input.clock_anchor);
        let notes = file_shown::Notes {
            start: run_start(scan),
            flagged: &scan.flagged_paths,
        };
        match tab {
            FileTab::Read => {
                let rows = file_category::with_time(&scan.read, clock);
                draw(ui, tab, file_tabs::READ_HEADERS, &rows, &notes);
            }
            FileTab::Changed => {
                draw(ui, tab, file_tabs::CHANGED_HEADERS, &scan.changed, &notes);
            }
            _ => {
                let source = if tab == FileTab::Opened {
                    &scan.opened
                } else {
                    &scan.file_tabs[index - 8].rows
                };
                let rows = file_category::with_time(source, clock);
                draw(ui, tab, EVENT_HEADERS, &rows, &notes);
            }
        }
    }
}

/// `headers` and `rows` of a tab's table drawn in the columns it shows (see
/// [`file_shown`]). Details still shows the selected row in full.
fn draw(
    ui: &mut egui::Ui,
    tab: FileTab,
    headers: &[&str],
    rows: &[Vec<Cell>],
    notes: &file_shown::Notes<'_>,
) {
    let shown_headers = file_shown::headers(tab.slot(), headers);
    let shown = file_shown::shown(tab.slot(), rows, notes);
    table_rows(ui, tab.table_id(), &shown_headers, &shown);
    details::refresh(ui.ctx(), tab.table_id(), headers, rows);
}

