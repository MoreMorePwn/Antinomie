// SPDX-License-Identifier: GPL-3.0-only
//! The File activity section: its tabs, filters and tables.
use super::file_category::EVENT_HEADERS;
use super::*;

pub(super) const READ_HEADERS: &[&str] = &[
    "Time",
    "Path",
    "Process (PID / TID)",
    "Transferred / content",
    "Result",
    "Location",
    "Access",
    "Evidence",
];
/// The Opened table shows only these columns of [`EVENT_HEADERS`]: time, path,
/// PID/TID, result, evidence. The rest stay in Details.
pub(super) const OPENED_COLUMNS: &[usize] = &[0, 3, 5, 6, 9];
/// The Read table shows time, path, PID/TID, content, result and evidence of
/// [`READ_HEADERS`]; Location and Access stay in Details.
pub(super) const READ_COLUMNS: &[usize] = &[0, 1, 2, 3, 4, 7];
/// The column of the full row behind column `shown` of a table's slot.
pub(super) fn full_column(slot: usize, shown: usize) -> usize {
    let columns = match slot {
        1 => OPENED_COLUMNS,
        5 => READ_COLUMNS,
        _ => return shown,
    };
    columns.get(shown).copied().unwrap_or(shown)
}

pub(super) const CHANGED_HEADERS: &[&str] = &[
    "Time",
    "Path",
    "Process (PID / TID)",
    "Lifecycle",
    "Diff count",
    "Location",
    "Evidence",
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
    /// start on; Failed attempts starts off.
    pub(super) fn file_toggles(&mut self, ui: &mut egui::Ui) {
        use crate::widgets::toggle_chip;
        let failed = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.failed_attempts);
        let visibility = &mut self.scan_request.file_visibility;
        let mut changed = false;
        if toggle_chip(ui, "Hide stdio", visibility.hide_standard_io, None)
            .on_hover_text("Hide stdin, stdout, stderr")
            .clicked()
        {
            visibility.hide_standard_io = !visibility.hide_standard_io;
            changed = true;
        }
        if toggle_chip(ui, "Hide library", visibility.hide_libraries, None)
            .on_hover_text("Hide shared libraries and the loader cache")
            .clicked()
        {
            visibility.hide_libraries = !visibility.hide_libraries;
            changed = true;
        }
        if toggle_chip(ui, "Failed attempts", visibility.show_failed, Some(failed))
            .on_hover_text("Calls the kernel refused, in the change tabs and Changed files. They do not count as changes. Opened and Read always list failed attempts with their result.")
            .clicked()
        {
            visibility.show_failed = !visibility.show_failed;
            changed = true;
        }
        if changed {
            for index in file_slots() {
                self.scan_request.offsets[index] = 0;
            }
            self.request_query_refresh();
        }
    }

    pub(super) fn files(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        self.file_tabs(ui);
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
        match tab {
            FileTab::Read => {
                let rows = file_category::with_time(&scan.read, clock);
                compact(
                    ui,
                    "triage-read",
                    file_tabs::READ_HEADERS,
                    &rows,
                    READ_COLUMNS,
                );
            }
            FileTab::Changed => {
                egui::ScrollArea::horizontal()
                    .id_salt("changed-file-columns")
                    .show(ui, |ui| {
                        ui.set_min_width(930.0);
                        table_rows(
                            ui,
                            "triage-changed",
                            file_tabs::CHANGED_HEADERS,
                            &scan.changed,
                        );
                    });
                details::refresh(
                    ui.ctx(),
                    "triage-changed",
                    file_tabs::CHANGED_HEADERS,
                    &scan.changed,
                );
            }
            _ => {
                let source = if tab == FileTab::Opened {
                    &scan.opened
                } else {
                    &scan.file_tabs[index - 8].rows
                };
                let rows = file_category::with_time(source, clock);
                if tab == FileTab::Opened {
                    compact(ui, tab.table_id(), EVENT_HEADERS, &rows, OPENED_COLUMNS);
                } else {
                    table(ui, tab.table_id(), EVENT_HEADERS, &rows);
                }
            }
        }
    }
}

/// `headers` and `rows` with only the columns at `keep` drawn. Details still
/// shows the selected row in full.
fn compact(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>], keep: &[usize]) {
    let shown_headers: Vec<&str> = keep.iter().map(|&index| headers[index]).collect();
    let shown: Vec<Vec<Cell>> = rows
        .iter()
        .map(|row| {
            keep.iter()
                .filter_map(|&index| row.get(index).cloned())
                .collect()
        })
        .collect();
    egui::ScrollArea::horizontal()
        .id_salt((id, "columns"))
        .auto_shrink([false, true])
        .show(ui, |ui| table_rows(ui, id, &shown_headers, &shown));
    details::refresh(ui.ctx(), id, headers, rows);
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
    /// call is not counted in any badge and has a row only when asked for. Reads
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
        // Opened and Read list failed attempts with their result; the toggle
        // is for the change categories.
        let toggled = |hit: &&file_category::Hit| {
            !matches!(hit.category.tab(), FileTab::Opened | FileTab::Read)
        };
        if failed && hits.iter().any(|hit| toggled(&hit)) {
            counts.failed_attempts += 1;
        }
        for hit in hits
            .iter()
            .filter(|hit| hit.category != file_category::Category::Read)
        {
            let tab = hit.category.tab();
            let listed = !toggled(&hit);
            if !failed || listed {
                match tab {
                    FileTab::Opened => counts.opened += 1,
                    _ => counts.tabs[tab.slot() - 8] += 1,
                }
            } else if !request.file_visibility.show_failed {
                continue;
            }
            let row = file_category::category_row(files, call, event, *hit);
            let at = Self::position(tab);
            let keeps = request
                .file_visibility
                .keeps_with(&row, listed || request.file_visibility.show_failed);
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
