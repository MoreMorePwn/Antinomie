// SPDX-License-Identifier: MIT
//! The context menu every static analysis table row offers, and the floating
//! details and bytes windows its items open. A window holds a copy of its
//! row, so it outlives the filter, sort and tab that showed the row.
use super::records::{self, Column};
use super::ReportAction;
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisKind, AnalysisRange, AnalysisReport, AnalysisSpecimenPage,
};
use eframe::egui;

/// Bytes shown per page of the bytes window.
const PAGE_SIZE: u64 = 256;

/// What a row's menu asked the view to do.
pub(super) enum RowCommand {
    Details(AnalysisEntry),
    Bytes(AnalysisEntry, AnalysisRange),
    /// Open the Content tab at this file offset.
    ShowInContent(u64),
}

/// The one details window and the one bytes window a view may have open.
#[derive(Default)]
pub(super) struct RowWindows {
    details: Option<AnalysisEntry>,
    bytes: Option<BytesWindow>,
}

struct BytesWindow {
    entry: AnalysisEntry,
    range: AnalysisRange,
    /// The page last asked for; None until the window has asked once.
    requested: Option<(u64, usize)>,
}

/// "Copy offset" for a column titled "Offset".
pub(super) fn copy_label(title: &str) -> String {
    format!("Copy {}", title.to_lowercase())
}

/// The menu items of one row. `cells` holds each visible column's title and
/// its complete value; `content` offers the Content tab as a destination.
pub(super) fn menu(
    ui: &mut egui::Ui,
    cells: &[(&str, String)],
    entry: &AnalysisEntry,
    specimen_len: Option<u64>,
    content: bool,
) -> Option<RowCommand> {
    let mut command = None;
    ui.set_min_width(190.0);
    for (title, value) in cells {
        if ui.button(copy_label(title)).clicked() {
            ui.ctx().copy_text(value.clone());
            ui.close_menu();
        }
    }
    if ui.button("Copy row").clicked() {
        let row: Vec<_> = cells.iter().map(|(_, value)| value.as_str()).collect();
        ui.ctx().copy_text(row.join("\t"));
        ui.close_menu();
    }
    ui.separator();
    if ui.button("Show details…").clicked() {
        command = Some(RowCommand::Details(entry.clone()));
        ui.close_menu();
    }
    if let Some(range) = records::file_range(entry, specimen_len) {
        if ui.button("Show bytes…").clicked() {
            command = Some(RowCommand::Bytes(entry.clone(), range));
            ui.close_menu();
        }
    }
    if let Some(offset) = records::file_offset(entry, specimen_len).filter(|_| content) {
        if ui
            .button("Show in Content")
            .on_hover_text(format!("Open the file content at 0x{offset:x}"))
            .clicked()
        {
            command = Some(RowCommand::ShowInContent(offset));
            ui.close_menu();
        }
    }
    command
}

impl RowWindows {
    pub(super) fn open_details(&mut self, entry: AnalysisEntry) {
        self.details = Some(entry);
    }

    /// Open the window a command names. Navigation commands belong to the caller.
    pub(super) fn open(&mut self, command: RowCommand) {
        match command {
            RowCommand::Details(entry) => self.open_details(entry),
            RowCommand::Bytes(entry, range) => {
                self.bytes = Some(BytesWindow {
                    entry,
                    range,
                    requested: None,
                });
            }
            RowCommand::ShowInContent(_) => {}
        }
    }

    /// Draw the open windows. The bytes window shares the specimen preview with
    /// the Content tab, so it waits (`bytes_visible` false) while that tab is
    /// shown and reads its page again afterwards. `idle` is false while the
    /// caller already has an action for this frame.
    pub(super) fn show(
        &mut self,
        ctx: &egui::Context,
        scope: (&str, Option<AnalysisKind>),
        report: &AnalysisReport,
        preview: Option<&Result<AnalysisSpecimenPage, String>>,
        bytes_visible: bool,
        idle: bool,
    ) -> Option<ReportAction> {
        let salt = (scope.0, scope.1.map(AnalysisKind::label));
        let screen = ctx.screen_rect();
        let mut action = None;
        if let Some(entry) = &self.details {
            let mut open = true;
            crate::widgets::window(title("Details", entry))
                .id(egui::Id::new(("analysis-row-details", salt)))
                .open(&mut open)
                .default_size([420.0, 320.0])
                .default_pos([(screen.right() - 440.0).max(0.0), screen.top() + 96.0])
                .show(ctx, |ui| details(ui, report.specimen_len, entry));
            if !open {
                self.details = None;
            }
        }
        if let Some(window) = &mut self.bytes {
            if !bytes_visible {
                window.requested = None;
                return action;
            }
            let mut open = true;
            crate::widgets::window(title("Bytes", &window.entry))
                .id(egui::Id::new(("analysis-row-bytes", salt)))
                .open(&mut open)
                .default_size([640.0, 360.0])
                .default_pos([
                    (screen.right() - 660.0).max(0.0),
                    (screen.bottom() - 380.0).max(screen.top() + 140.0),
                ])
                .show(ctx, |ui| {
                    action = bytes(ui, report, window, preview, idle);
                });
            if !open {
                self.bytes = None;
            } else if !idle && window.requested.is_none() {
                ctx.request_repaint();
            }
        }
        action
    }
}

/// A window title: the kind of window and what names the row, shortened.
/// A string is named by its text; its label only says the encoding.
fn title(kind: &str, entry: &AnalysisEntry) -> String {
    const LIMIT: usize = 40;
    let name = match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::String { .. }) => entry.value.clone(),
        _ => Column::Name.text(entry),
    };
    let name = name.lines().next().unwrap_or_default();
    let mut shown: String = name.chars().take(LIMIT).collect();
    if name.chars().nth(LIMIT).is_some() {
        shown.push('…');
    }
    format!("{kind} · {shown}")
}

fn copy_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        crate::analysis::strong(ui, label);
        if ui
            .button(egui_phosphor::regular::COPY)
            .on_hover_text(format!("Copy full {label}"))
            .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
    });
    ui.add(egui::Label::new(egui::RichText::new(value).monospace()).wrap());
}

pub(super) fn details(ui: &mut egui::Ui, specimen_len: Option<u64>, entry: &AnalysisEntry) {
    egui::ScrollArea::both()
        .id_salt("analysis-item-detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            copy_value(ui, &entry.label, &entry.value);
            if let Some(record) = &entry.record {
                ui.label(format!("Record {}", record.id));
                if let Some(location) = &record.location {
                    ui.monospace(format!("{:?}: 0x{:x}", location.kind, location.value));
                    if let Some(range) = location.file_range {
                        ui.monospace(format!(
                            "File range: 0x{:x} + {}",
                            range.offset,
                            crate::values::file_size(range.len)
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
            if records::file_range(entry, specimen_len).is_none() {
                ui.separator();
                ui.weak("No proven retained file range for byte preview.");
            }
        });
}

/// Bounded pages of the row's retained range, read on request.
fn bytes(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    window: &mut BytesWindow,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
    idle: bool,
) -> Option<ReportAction> {
    let range = window.range;
    let read = |offset: u64| {
        let data_len = usize::try_from((range.offset + range.len - offset).min(PAGE_SIZE))
            .unwrap_or(PAGE_SIZE as usize);
        (
            (offset, data_len),
            ReportAction::ReadSpecimen {
                report_id: report.id.clone(),
                offset,
                data_len,
            },
        )
    };
    let mut action = None;
    if window.requested.is_none() {
        if !idle {
            crate::theme::loading_weak(ui, "Waiting to read the specimen…");
            return None;
        }
        let (page, next) = read(range.offset);
        window.requested = Some(page);
        action = Some(next);
    }
    let (offset, data_len) = window.requested.unwrap_or((range.offset, 0));
    ui.horizontal(|ui| {
        let previous = offset.saturating_sub(PAGE_SIZE).max(range.offset);
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
            let (page, next) = read(offset);
            window.requested = Some(page);
            action = Some(next);
        }
        ui.monospace(format!(
            "File offset 0x{offset:x} / {} of 0x{:x} + {}",
            crate::values::file_size(data_len as u64),
            range.offset,
            crate::values::file_size(range.len)
        ));
    });
    let (offset, data_len) = window.requested.unwrap_or((offset, data_len));
    egui::ScrollArea::both()
        .id_salt("analysis-item-bytes")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // A dump row is one line however narrow the window.
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
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
                    crate::activity::error(ui, reason);
                }
                _ => {
                    ui.label("Awaiting matching specimen preview.");
                }
            }
        });
    action
}

pub(super) fn preview_matches(
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
