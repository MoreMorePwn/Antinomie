// SPDX-License-Identifier: MIT
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

    /// Hover text naming the operations a tab gathers.
    pub(super) fn hint(self) -> &'static str {
        match self {
            Self::Opened => "open, openat, openat2, creat that succeeded, with access mode",
            Self::Created => "O_CREAT that made the file, creat, mkdir, mknod, memfd_create, O_TMPFILE; inferred when the path was not seen earlier",
            Self::Read => "read, readv, pread64, preadv and the source of kernel-side copies",
            Self::Written => "write, writev, pwrite64, pwritev, truncate, ftruncate, fallocate, O_TRUNC",
            Self::Deleted => "unlink, unlinkat, rmdir",
            Self::Renamed => "rename, renameat, renameat2: old path to new path",
            Self::Executed => "execve, execveat",
            Self::Attributes => "chmod and chown family, utime family (timestamps), extended attributes",
            Self::Probed => "stat family, statx, access, faccessat, readlink",
            Self::Other => "link, symlink, sendfile, copy_file_range, splice, FICLONE, executable or shared writable mappings, getdents, inotify, fanotify, flock, fcntl locks",
            Self::Changed => "One row per file: what happened to it, from created to deleted",
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
    pub(super) fn files(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        self.file_tabs(ui);
        let tab = self.files;
        let index = tab.slot();
        ui.weak(tab.hint());
        let (retained, total) = self.scan.as_ref().map_or((0, 0), |scan| {
            let (rows, omitted) = scan.file_rows(tab);
            (rows, rows as u64 + omitted)
        });
        self.query_controls(ui, index, FILE_FIELDS, tab.example(), retained, total);
        let Some(scan) = &self.scan else {
            theme::loading_weak(ui, "Indexing this run’s files…");
            return;
        };
        let clock = scan.clock_anchor.or(input.clock_anchor);
        match tab {
            FileTab::Read => {
                let rows = file_category::with_time(&scan.read, clock);
                table(ui, "triage-read", file_tabs::READ_HEADERS, &rows);
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
                table(ui, tab.table_id(), EVENT_HEADERS, &rows);
            }
        }
    }
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
        let slots = std::iter::once(1).chain(8..SLOTS);
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
        if failed && !hits.is_empty() {
            counts.failed_attempts += 1;
        }
        for hit in hits
            .iter()
            .filter(|hit| hit.category != file_category::Category::Read)
        {
            let tab = hit.category.tab();
            if !failed {
                match tab {
                    FileTab::Opened => counts.opened += 1,
                    _ => counts.tabs[tab.slot() - 8] += 1,
                }
            } else if !request.file_visibility.show_failed {
                continue;
            }
            let row = file_category::category_row(files, call, event, *hit);
            let at = Self::position(tab);
            if request.file_visibility.keeps(&row) && self.queries[at].keep_table(&row[0].values) {
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
