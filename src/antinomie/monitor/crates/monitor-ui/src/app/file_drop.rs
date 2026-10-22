// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Dropping one host file onto the main window opens Upload with it filled in.
//!
//! Only metadata (`is_file`) of the dropped path is read; the file's contents
//! are never opened, parsed or executed on the host. The upload itself still
//! waits for the user to confirm in the dialog.
use super::*;
use std::path::Path;

/// Why a drop cannot fill the Upload form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Several,
    Folder,
    NoPath,
    NotFile,
    PathEncoding,
    Pending,
    NotRunning,
}

impl Refusal {
    fn title(self) -> &'static str {
        match self {
            Self::Several => "Drop one file at a time",
            Self::Folder => "Folders cannot be uploaded",
            Self::NoPath => "This item has no host file path",
            Self::NotFile => "Only regular files can be uploaded",
            Self::PathEncoding => "This file path is not valid UTF-8",
            Self::Pending => "An upload is already in progress",
            Self::NotRunning => "A running VM is required to upload",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Several => "Drop a single file onto the window.",
            Self::Folder => "Drop a single file instead.",
            Self::NoPath => "Use Choose file… in the Upload dialog instead.",
            Self::NotFile => "Drop a single regular file instead.",
            Self::PathEncoding => "Use Choose file… in the Upload dialog instead.",
            Self::Pending => "Wait for it to finish, then drop the file again.",
            Self::NotRunning => "Start the selected VM, then drop the file again.",
        }
    }

    /// The short notice shown on the status line after a refused drop.
    fn notice(self) -> String {
        format!("Drop not used: {}. {}", self.title(), self.detail())
    }
}

/// Picks the single regular file of a drop. While `hovering`, platforms often
/// withhold the path, so a missing path is not yet a refusal.
fn classify(items: &[Option<&Path>], hovering: bool) -> Result<Option<PathBuf>, Refusal> {
    let [item] = items else {
        return Err(Refusal::Several);
    };
    let Some(path) = item else {
        return if hovering {
            Ok(None)
        } else {
            Err(Refusal::NoPath)
        };
    };
    // Metadata only; a symbolic link to a file is followed like the file chooser does.
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(Refusal::Folder),
        Ok(metadata) if !metadata.is_file() => Err(Refusal::NotFile),
        Ok(_) if path.to_str().is_none() || path.file_name().and_then(|n| n.to_str()).is_none() => {
            Err(Refusal::PathEncoding)
        }
        Ok(_) => Ok(Some(path.to_path_buf())),
        Err(_) if hovering => Ok(None),
        Err(_) => Err(Refusal::NotFile),
    }
}

impl MonitorApp {
    /// Why an upload cannot start now, if it cannot.
    fn drop_unavailable(&self) -> Option<Refusal> {
        if self.pending_upload.is_some() {
            Some(Refusal::Pending)
        } else if self.closing || !self.running() {
            Some(Refusal::NotRunning)
        } else {
            None
        }
    }

    /// Handles a file dropped this frame. Call before the dialogs are drawn.
    pub(super) fn accept_dropped_file(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>()
        });
        if dropped.is_empty() {
            return;
        }
        let items: Vec<Option<&Path>> = dropped.iter().map(|path| path.as_deref()).collect();
        let path = match classify(&items, false) {
            Err(refusal) => {
                self.report_warning(refusal.notice());
                return;
            }
            Ok(path) => path,
        };
        if let Some(refusal) = self.drop_unavailable() {
            self.report_warning(refusal.notice());
            return;
        }
        let Some(path) = path else {
            return;
        };
        // The same path as Choose file…: opening the dialog starts a new file
        // generation, and the form derives the guest path from the file name.
        self.open_upload();
        self.accept_upload_file(self.upload_browser.generation, path.clone());
        if self.upload_browser.selected.as_ref() == Some(&path) {
            self.status = "Review the upload destination, then press Upload".into();
        }
        ctx.request_repaint();
    }

    /// Dims the window and says what dropping the hovered file will do.
    pub(super) fn file_drop_overlay(&self, ctx: &egui::Context) {
        let hovered = ctx.input(|input| {
            input
                .raw
                .hovered_files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>()
        });
        if hovered.is_empty() {
            return;
        }
        // The same file hovers for many frames: ask the disk about it twice a second.
        let id = egui::Id::new("file_drop_hover");
        let cached =
            ctx.data(|data| data.get_temp::<(Vec<Option<PathBuf>>, Instant, Option<Refusal>)>(id));
        let hover_refusal = match cached {
            Some((paths, at, refusal))
                if paths == hovered && at.elapsed() < Duration::from_millis(500) =>
            {
                refusal
            }
            _ => {
                let items: Vec<Option<&Path>> =
                    hovered.iter().map(|path| path.as_deref()).collect();
                let refusal = classify(&items, true).err();
                ctx.data_mut(|data| {
                    data.insert_temp(id, (hovered.clone(), Instant::now(), refusal))
                });
                refusal
            }
        };
        let refusal = hover_refusal.or_else(|| self.drop_unavailable());
        let (title, detail, title_color) = match refusal {
            Some(refusal) => (refusal.title().to_owned(), refusal.detail(), theme::warn()),
            None => {
                let name = self
                    .selected_vm()
                    .map(|vm| vm.name.as_str())
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("the VM");
                (
                    format!("Drop a file to upload it to {name}"),
                    "You can review the destination before it is sent.",
                    theme::heading(),
                )
            }
        };
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("file_drop_overlay"),
        ));
        let screen = ctx.screen_rect();
        painter.rect_filled(screen, 0.0, theme::bg().gamma_multiply(0.82));
        let wrap = (screen.width() - 96.0).clamp(160.0, 560.0);
        let title_galley = painter.layout(
            title,
            egui::TextStyle::Heading.resolve(&ctx.style()),
            title_color,
            wrap,
        );
        let detail_galley = painter.layout(
            detail.to_owned(),
            egui::TextStyle::Body.resolve(&ctx.style()),
            theme::text(),
            wrap,
        );
        let gap = 8.0;
        let padding = egui::vec2(28.0, 20.0);
        let inner = egui::vec2(
            title_galley.size().x.max(detail_galley.size().x),
            title_galley.size().y + gap + detail_galley.size().y,
        );
        let card = egui::Rect::from_center_size(screen.center(), inner + padding * 2.0);
        painter.rect_filled(card, 8.0, theme::raised());
        painter.rect_stroke(
            card,
            8.0,
            egui::Stroke::new(2.0_f32, theme::blue()),
            egui::StrokeKind::Inside,
        );
        let top = card.min + padding;
        painter.galley(
            egui::pos2(card.center().x - title_galley.size().x / 2.0, top.y),
            title_galley.clone(),
            title_color,
        );
        painter.galley(
            egui::pos2(
                card.center().x - detail_galley.size().x / 2.0,
                top.y + title_galley.size().y + gap,
            ),
            detail_galley,
            theme::text(),
        );
    }
}
