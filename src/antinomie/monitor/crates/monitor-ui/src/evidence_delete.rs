// SPDX-License-Identifier: GPL-3.0-only
//! Right-click Delete of saved network captures and process cores: the menu
//! item and the wording of the confirmation. The deletion itself is the
//! backend's `Command::DeleteEvidence`.
use crate::theme;
use antinomie_monitor_core::{byte_size::file_size, evidence_delete::measure, EvidenceItem};
use eframe::egui::{self, RichText};
use std::path::Path;

/// What kind of evidence the user asked to delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Network,
    Core,
    /// An imported core: only Antinomie's results go; the file stays.
    ImportedCore,
    /// A saved disk dump: its image, record and extractions.
    Disk,
    /// An imported disk image: only the record and extractions go.
    ImportedDisk,
}

/// One item the user asked to delete, with what the confirmation says of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Deletion {
    pub kind: Kind,
    pub item: EvidenceItem,
    /// The name the lists show for it.
    pub name: String,
    /// Its size, as the confirmation words it.
    pub size: String,
}

impl Deletion {
    pub(crate) fn network(file: &Path, name: &str) -> Self {
        Self {
            kind: Kind::Network,
            item: EvidenceItem::NetworkCapture {
                file: file.to_path_buf(),
            },
            name: name.to_owned(),
            size: size_text(file),
        }
    }

    pub(crate) fn core(directory: &Path, name: &str, kind: Kind) -> Self {
        Self {
            kind,
            item: EvidenceItem::ProcessCore {
                directory: directory.to_path_buf(),
            },
            name: name.to_owned(),
            size: size_text(directory),
        }
    }

    pub(crate) fn disk(directory: &Path, name: &str, imported: bool) -> Self {
        Self {
            kind: if imported {
                Kind::ImportedDisk
            } else {
                Kind::Disk
            },
            item: EvidenceItem::DiskDump {
                directory: directory.to_path_buf(),
            },
            name: name.to_owned(),
            // An imported image is not inside the folder and is not deleted.
            size: size_text(directory),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        match &self.item {
            EvidenceItem::NetworkCapture { file } => file,
            EvidenceItem::ProcessCore { directory } | EvidenceItem::DiskDump { directory } => {
                directory
            }
        }
    }

    pub(crate) fn title(&self) -> &'static str {
        match self.kind {
            Kind::Network => "Delete network capture",
            Kind::Core | Kind::ImportedCore => "Delete core dump",
            Kind::Disk | Kind::ImportedDisk => "Delete disk dump",
        }
    }

    pub(crate) fn text(&self) -> String {
        let (what, removes) = match self.kind {
            Kind::Network => (
                "network capture",
                "The pcap and its metadata and annotation files are removed from disk.",
            ),
            Kind::Core => (
                "core dump",
                "The core file, its metadata and its analysis results are removed from disk.",
            ),
            Kind::ImportedCore => (
                "imported core",
                "Its analysis results are removed from disk; the original core file stays where it is.",
            ),
            Kind::Disk => (
                "disk dump",
                "The disk image, its record and the files extracted from it are removed from disk.",
            ),
            Kind::ImportedDisk => (
                "imported disk image",
                "Its record and the files extracted from it are removed from disk; the original image file stays where it is.",
            ),
        };
        format!(
            "Delete the {what} \"{}\" ({})? {removes} This can't be undone.",
            self.name, self.size
        )
    }
}

/// The size of a file or folder for a confirmation; a figure cut short by the
/// count limit says so.
fn size_text(path: &Path) -> String {
    let found = measure(path);
    if found.truncated {
        format!("at least {}", file_size(found.bytes))
    } else {
        file_size(found.bytes)
    }
}

/// Why a capture the running boot may still write cannot be deleted.
pub(crate) const CAPTURE_LIVE: &str = "The live capture can't be deleted. Stop the capture first.";
pub(crate) const CAPTURE_WRITING: &str =
    "This capture is still being written. Stop it before deleting it.";
pub(crate) const CORE_CAPTURING: &str =
    "This core is still being captured. Wait for it, or cancel it, before deleting it.";

/// The last item of a row's right-click menu: a red Delete…, disabled with
/// `blocked` as its tooltip while the item is still being written. True when
/// it was clicked.
pub(crate) fn menu_item(ui: &mut egui::Ui, blocked: Option<&str>) -> bool {
    ui.separator();
    let button = ui.add_enabled(
        blocked.is_none(),
        egui::Button::new(RichText::new("Delete…").color(theme::error())),
    );
    let button = match blocked {
        Some(reason) => button.on_disabled_hover_text(reason),
        None => button.on_hover_text("Permanently delete this item from the recording folder"),
    };
    if button.clicked() {
        ui.close_menu();
        return true;
    }
    false
}
