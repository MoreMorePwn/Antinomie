// SPDX-License-Identifier: GPL-3.0-only
//! The File activity section: its tabs, filters and tables.
use super::file_category::EVENT_HEADERS;
use super::*;

pub(super) const READ_HEADERS: &[&str] = &[
    "Time",
    "Path",
    "Process",
    "Transferred / content",
    "Result",
    "Location",
    "Access",
    "Evidence",
];
/// The Opened table shows these columns of [`EVENT_HEADERS`]: time, path,
/// process and result. Location is a badge on the path; the rest stay in
/// Details.
pub(super) const OPENED_COLUMNS: &[usize] = &[0, 3, 5, 6];
/// The other operation tables show every column of [`EVENT_HEADERS`] but
/// Location (a badge) and Evidence (Details opens the original syscall).
pub(super) const OPERATION_COLUMNS: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 8];
/// The Read table shows time, path, process, content and result of
/// [`READ_HEADERS`]; Location and Access stay in Details.
pub(super) const READ_COLUMNS: &[usize] = &[0, 1, 2, 3, 4];
/// The Changed table: time, path, process, lifecycle, changes, type and digest.
pub(super) const CHANGED_COLUMNS: &[usize] = &[0, 1, 2, 3, 4, 7, 8];

/// The stored columns the table of `slot` draws, in order.
pub(super) fn shown_columns(slot: usize) -> &'static [usize] {
    match slot {
        1 => OPENED_COLUMNS,
        2 => CHANGED_COLUMNS,
        5 => READ_COLUMNS,
        8..=15 => OPERATION_COLUMNS,
        _ => &[],
    }
}
/// The column of the full row behind column `shown` of a table's slot.
pub(super) fn full_column(slot: usize, shown: usize) -> usize {
    if matches!(slot, ENDPOINT_SLOT | DOMAIN_SLOT | TLS_SLOT) {
        return net_tabs::stored_column(slot, shown);
    }
    shown_columns(slot).get(shown).copied().unwrap_or(shown)
}

pub(super) const CHANGED_HEADERS: &[&str] = &[
    "Time",
    "Path",
    "Process",
    "Lifecycle",
    "Changes",
    "Location",
    "Evidence",
    "Type",
    "SHA-256",
];

impl FileTab {
    /// Tabs in display order.
    pub(super) const ALL: [Self; 11] = [
        Self::Opened,
        Self::Created,
        Self::Read,
        Self::Written,
        Self::Deleted,
        Self::Renamed,
        Self::Executed,
        Self::Attributes,
        Self::Probed,
        Self::Other,
        Self::Changed,
    ];

    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Opened => "Opened files",
            Self::Created => "Created files",
            Self::Read => "Read files",
            Self::Written => "Written / resized",
            Self::Deleted => "Deleted files",
            Self::Renamed => "Renamed / moved",
            Self::Executed => "Executed files",
            Self::Attributes => "Attributes",
            Self::Probed => "Metadata probed",
            Self::Other => "Other",
            Self::Changed => "Changed files",
        }
    }

    /// Query slot of the tab's filter, sort and page.
    pub(super) fn slot(self) -> usize {
        match self {
            Self::Opened => 1,
            Self::Changed => 2,
            Self::Read => 5,
            Self::Created => 8,
            Self::Written => 9,
            Self::Deleted => 10,
            Self::Renamed => 11,
            Self::Executed => 12,
            Self::Attributes => 13,
            Self::Probed => 14,
            Self::Other => 15,
        }
    }

    pub(super) fn example(self) -> &'static str {
        match self {
            Self::Opened | Self::Read => "file.path contains \"/etc\"",
            Self::Created => "file.location == \"temp\"",
            Self::Written => "file.result == \"succeeded\" and file.written_size > 0",
            Self::Deleted => "file.location == \"persistence\"",
            Self::Renamed => "file.new_path contains \"/tmp\"",
            Self::Executed => "file.access_by == \"descriptor\"",
            Self::Attributes => "file.mode_flags == \"+x\"",
            Self::Probed => "file.errno == \"ENOENT\"",
            Self::Other => "file.category == \"Linked\"",
            Self::Changed => "file.lifecycle contains \"deleted\"",
        }
    }
}

/// Slots of every file table, to reset when a visibility toggle changes.
pub(super) fn file_slots() -> impl Iterator<Item = usize> {
    FileTab::ALL.into_iter().map(FileTab::slot)
}

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

/// The start of the run, in the guest's nanoseconds: when its first task was
/// first seen, else its first file call.
fn run_start(scan: &ArchiveScan) -> Option<u64> {
    scan.process
        .iter()
        .filter_map(|node| node.first_ns)
        .min()
        .or_else(|| {
            scan.file_activity
                .files
                .iter()
                .map(|file| file.first_ns)
                .min()
        })
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
    let keep = file_tabs::shown_columns(tab.slot());
    let shown_headers: Vec<&str> = keep.iter().map(|&index| headers[index]).collect();
    let shown = file_shown::shown(tab.slot(), rows, notes);
    table_rows(ui, tab.table_id(), &shown_headers, &shown);
    details::refresh(ui.ctx(), tab.table_id(), headers, rows);
}

impl ArchiveScan {
    /// Rows kept for a tab and the matches left out of them.
    pub(super) fn file_rows(&self, tab: FileTab) -> (usize, u64) {
        match tab {
            FileTab::Opened => (self.opened.len(), self.opened_omitted),
            FileTab::Read => (self.read.len(), self.read_omitted),
            FileTab::Changed => (self.changed.len(), self.changed_omitted),
            _ => {
                let kept = &self.file_tabs[tab.slot() - 8];
                (kept.rows.len(), kept.omitted)
            }
        }
    }
}

impl FileTab {
    pub(super) fn table_id(self) -> &'static str {
        match self {
            Self::Opened => "triage-opened",
            Self::Created => "triage-created",
            Self::Read => "triage-read",
            Self::Written => "triage-written",
            Self::Deleted => "triage-deleted",
            Self::Renamed => "triage-renamed",
            Self::Executed => "triage-executed",
            Self::Attributes => "triage-attributes",
            Self::Probed => "triage-probed",
            Self::Other => "triage-other",
            Self::Changed => "triage-changed",
        }
    }
}

/// Routes each file call to the operation tabs it belongs to: counts it, and
/// keeps its row when the tab's filter and the visibility toggles allow.
pub(super) struct TabSink {
    /// Opened first, then the operation tabs in slot order from 8.
    pages: Vec<sorting::Page<Vec<Cell>>>,
    queries: Vec<query::Compiled>,
}

impl TabSink {
    fn position(tab: FileTab) -> usize {
        match tab {
            FileTab::Opened => 0,
            other => other.slot() - 7,
        }
    }

    pub(super) fn new(request: &ScanRequest, cancel: &Arc<AtomicBool>) -> Self {
        let slots = std::iter::once(1).chain(8..8 + FILE_TABS);
        Self {
            pages: slots
                .clone()
                .map(|slot| sorting::Page::new(request, slot, cancel))
                .collect(),
            queries: slots
                .map(|slot| query::compile_table(&request.filters[slot], FILE_FIELDS))
                .collect(),
        }
    }

    /// `hits` is the call's classification made before it was tracked. A failed
    /// call has a row, and is in its tab's badge, only when the chip shows it. Reads
    /// belong to the Read index and are left to it.
    pub(super) fn observe(
        &mut self,
        request: &ScanRequest,
        counts: &mut normalized::Counts,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        hits: &[file_category::Hit],
    ) -> Result<(), String> {
        let failed = file_category::outcome(call).failed();
        // The Failed attempts chip covers every table, Opened and Read included.
        if failed
            && hits
                .iter()
                .any(|hit| hit.category != file_category::Category::Read)
        {
            counts.failed_attempts += 1;
        }
        for hit in hits
            .iter()
            .filter(|hit| hit.category != file_category::Category::Read)
        {
            let tab = hit.category.tab();
            let show = !failed || request.file_visibility.show_failed;
            let row = file_category::category_row(files, call, event, *hit);
            counts.visibility[file_visibility::visibility_slot(tab)].note_failed(&row);
            if show {
                match tab {
                    FileTab::Opened => counts.opened += 1,
                    _ => counts.tabs[tab.slot() - 8] += 1,
                }
            } else {
                continue;
            }
            let at = Self::position(tab);
            counts.visibility[file_visibility::visibility_slot(tab)].add(
                request.file_visibility,
                &row,
                show,
            );
            let keeps = request.file_visibility.keeps_with(&row, show);
            if keeps && self.queries[at].keep_table(&row[0].values) {
                self.pages[at].push(row)?;
            }
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(FileRows, [FileRows; FILE_TABS]), String> {
        let mut pages = self.pages.drain(..);
        let (opened, opened_omitted, _) = pages.next().ok_or("missing Opened page")?.finish()?;
        let mut tabs: [FileRows; FILE_TABS] = Default::default();
        for (kept, page) in tabs.iter_mut().zip(pages) {
            let (rows, omitted, _) = page.finish()?;
            *kept = FileRows { rows, omitted };
        }
        Ok((
            FileRows {
                rows: opened,
                omitted: opened_omitted,
            },
            tabs,
        ))
    }
}
