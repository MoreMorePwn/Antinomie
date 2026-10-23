// SPDX-License-Identifier: GPL-3.0-only
//! Persisted syscall page size and cursor invalidation.
use super::*;

#[derive(Default)]
pub(super) struct TracePaging {
    pub page: u64,
    pub ranked: bool,
    pub window_start: u64,
    pub pending_start: Option<u64>,
    anchors: std::collections::BTreeMap<u64, u64>,
}

impl TracePaging {
    pub fn remember(&mut self, rank: u64, cursor: u64) {
        if self.anchors.len() >= 1024 {
            self.anchors.clear();
        }
        self.anchors.insert(rank, cursor);
    }
}

pub(super) fn deserialize_page_size<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<usize, D::Error> {
    i64::deserialize(deserializer).map(|size| usize::try_from(size.max(0)).unwrap_or(usize::MAX))
}

impl MonitorApp {
    pub(super) fn set_trace_page_size(&mut self, size: usize) {
        let size = size.min(i64::MAX as usize);
        if self.settings.trace_page_size == size {
            return;
        }
        self.settings.trace_page_size = size;
        // Cursors describe the old page boundaries, not call numbers. Restart
        // the same filtered view and let the reply retain selection by identity.
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_offset = 0;
        self.request_page(0);
    }

    pub(super) fn trace_windowed(&self) -> bool {
        self.settings.trace_page_size == 0 || self.settings.trace_page_size > 256
    }

    pub(super) fn trace_page_count(&self) -> u64 {
        if self.settings.trace_page_size == 0 {
            return 1;
        }
        self.archive_total
            .unwrap_or(0)
            .div_ceil(self.settings.trace_page_size as u64)
            .max(1)
    }

    pub(super) fn jump_trace_page(&mut self, page: u64) {
        let page = page.min(self.trace_page_count() - 1);
        self.trace_paging.page = page;
        self.archive_previous.clear();
        self.request_trace_window(page.saturating_mul(self.settings.trace_page_size as u64));
    }

    pub(super) fn request_trace_window(&mut self, start: u64) {
        let Some(directory) = self.prepare_trace_read() else {
            return;
        };
        let (rank, offset) = self
            .trace_paging
            .anchors
            .range(..=start)
            .next_back()
            .map_or((0, 0), |(&rank, &offset)| (rank, offset));
        let limit = if self.trace_windowed() {
            256
        } else {
            self.settings.trace_page_size
        };
        self.trace_paging.ranked = true;
        self.trace_paging.pending_start = Some(start);
        self.queue_archive(Request::InvocationRange {
            generation: self.archive_generation,
            directory,
            offset,
            skip: start - rank,
            limit,
            capture: self.selected_capture.is_some(),
            pid: self.selected_process,
            query: self.applied_filter.clone(),
            hidden_categories: self.archive_hidden_categories.clone(),
            cancel: Arc::clone(self.archive_read_cancel.as_ref().expect("prepared read")),
        });
        self.archive_pending = true;
    }

    pub(super) fn trace_archive_pager(&mut self, ui: &mut egui::Ui) {
        if self.trace_archive_directory().is_some() {
            let mut size = self.settings.trace_page_size.min(i64::MAX as usize) as i64;
            ui.label("Calls/page");
            if ui
                .add(egui::DragValue::new(&mut size).range(-1..=i64::MAX))
                .on_hover_text("Calls per page; 0 or -1 shows all matching calls in a virtual table. Saved across restarts. Large pages load visible rows in bounded windows.")
                .changed()
            {
                self.set_trace_page_size(size.max(0) as usize);
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_LEFT,
                "Previous archive page",
                !self.archive_pending && self.trace_paging.page > 0,
            ) {
                if self.trace_paging.ranked {
                    self.jump_trace_page(self.trace_paging.page - 1);
                } else if let Some(offset) = self.archive_previous.pop() {
                    self.trace_paging.page = self.trace_paging.page.saturating_sub(1);
                    self.request_page(offset);
                }
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_RIGHT,
                "Next archive page",
                !self.archive_pending
                    && self.settings.trace_page_size != 0
                    && (self.archive_next.is_some()
                        || self.trace_paging.page + 1 < self.trace_page_count()),
            ) {
                self.next_archive_page();
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Reload archive page",
                !self.archive_pending,
            ) {
                if self.trace_paging.ranked {
                    self.request_trace_window(self.trace_paging.window_start);
                } else {
                    let offset = if self.archive_page_generation != self.archive_generation
                        && self.archive_previous.is_empty()
                    {
                        0
                    } else {
                        self.archive_offset
                    };
                    self.request_page(offset);
                }
            }
            if self.archive_total.is_none()
                && !self.archive_pending
                && self.archive_page_generation == self.archive_generation
                && self.archive_error.is_none()
            {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    ui.label(format!(
                        "Page {} · counting matches…",
                        self.trace_paging.page + 1
                    ));
                });
            }
            if let Some(total) = self.archive_total {
                if self.settings.trace_page_size != 0 {
                    let mut page = self.trace_paging.page + 1;
                    ui.label("Go to page");
                    if ui
                        .add(egui::DragValue::new(&mut page).range(1..=self.trace_page_count()))
                        .on_hover_text(
                            "Type a page number to jump directly; the active filter is preserved",
                        )
                        .changed()
                    {
                        self.jump_trace_page(page - 1);
                    }
                }
                if self.archive_page_generation == self.archive_generation {
                    if self.settings.trace_page_size == 0 {
                        ui.label(format!(
                            "All {total} matching / {} saved calls · visible rows loaded on demand",
                            self.archive_source_total.unwrap_or(total)
                        ));
                    } else {
                        ui.label(format!(
                            "Page {} of {} · {} calls/page · {total} matching / {} saved calls",
                            self.trace_paging.page + 1,
                            self.trace_page_count(),
                            self.settings.trace_page_size,
                            self.archive_source_total.unwrap_or(total)
                        ));
                    }
                } else {
                    ui.label(format!(
                        "Previous results: {total} matching / {} saved calls",
                        self.archive_source_total.unwrap_or(total)
                    ));
                }
            }
            if self.archive_pending {
                theme::spinner(ui);
            }
            ui.label(if self.archive_pending {
                if self.archive_page.is_empty() {
                    "Reading archive matches…"
                } else {
                    "Reading matches · previous results shown"
                }
            } else if self.archive_page_generation != self.archive_generation
                && !self.archive_page.is_empty()
            {
                "Previous results · refresh to retry"
            } else {
                "History"
            });
        }
    }
}
