// SPDX-License-Identifier: GPL-3.0-only
//! What the Output files table adds to the memory dumps, core dumps and
//! captures a run's folder holds: VM snapshots and files a rule saved, the
//! artifacts of runs that were deleted (kept in Samples, deleted by you, with
//! the VM, in the sample record) and a short SHA-256 for every row.
//!
//! Hashes of big files are read on a thread and cached in the library, so
//! drawing the table never reads a file.
use super::{
    output_files::{Availability, Kind, Output},
    *,
};
use antinomie_monitor_core::samples::{
    artifact_target, short_hash, ArtifactFate, ArtifactKind, KeptArtifact, NoteRef, RefKind,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Hashes read so far, by path; and the paths being read.
static HASHES: Mutex<Option<Hashes>> = Mutex::new(None);

#[derive(Default)]
struct Hashes {
    known: HashMap<PathBuf, String>,
    pending: HashSet<PathBuf>,
}

impl Kind {
    pub(in crate::app::samples_page) fn core(self) -> ArtifactKind {
        match self {
            Kind::Memory => ArtifactKind::Memory,
            Kind::Core => ArtifactKind::Core,
            Kind::Capture => ArtifactKind::Capture,
            Kind::Snapshot => ArtifactKind::Snapshot,
            Kind::Saved => ArtifactKind::File,
            Kind::StaticReport => ArtifactKind::Static,
        }
    }

    pub(in crate::app::samples_page) fn of(kind: ArtifactKind) -> Kind {
        match kind {
            ArtifactKind::Memory => Kind::Memory,
            ArtifactKind::Core => Kind::Core,
            ArtifactKind::Capture => Kind::Capture,
            ArtifactKind::Snapshot => Kind::Snapshot,
            ArtifactKind::File => Kind::Saved,
            ArtifactKind::Static => Kind::StaticReport,
        }
    }
}

impl Output {
    /// "Core dump 9c41e2a0": the kind and the first 8 hex of its SHA-256.
    pub(in crate::app::samples_page) fn title(&self) -> String {
        format!("{} {}", self.kind.label(), short_hash(&self.hash))
    }

    pub(in crate::app::samples_page) fn kind_label(&self) -> &'static str {
        self.kind.label()
    }

    /// The file is where the table says it is.
    pub(in crate::app::samples_page) fn is_present(&self) -> bool {
        matches!(
            self.availability,
            Availability::InRun
                | Availability::Kept(_, _)
                | Availability::WithVm
                | Availability::InRecord
        )
    }

    /// The reference a note makes to this artifact.
    pub(in crate::app::samples_page) fn reference(&self) -> NoteRef {
        let name = if self.name.is_empty() {
            self.path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        } else {
            self.name.clone()
        };
        let mut label = format!("{} · run {}", self.title(), self.number);
        if !self.context.is_empty() {
            label.push_str(&format!(" · {}", self.context));
        }
        NoteRef::new(
            RefKind::Artifact,
            artifact_target(self.kind.core().as_str(), &self.vm_id, &self.run_id, &name),
            label,
        )
    }

    /// The short hash the table shows: read, or still being read.
    pub(in crate::app::samples_page) fn short(&self) -> String {
        if !self.hash.is_empty() {
            return short_hash(&self.hash);
        }
        match cached(&self.path) {
            Some(hash) => short_hash(&hash),
            None if self.path.as_os_str().is_empty() => "–".into(),
            None => "…".into(),
        }
    }
}

fn cached(path: &Path) -> Option<String> {
    HASHES.lock().ok()?.as_ref()?.known.get(path).cloned()
}

/// Start reading the hashes of the rows that have none yet (once per file).
pub(in crate::app::samples_page) fn request_hashes(
    ctx: &egui::Context,
    data_dir: &Path,
    outputs: &[Output],
) {
    let Ok(mut guard) = HASHES.lock() else {
        return;
    };
    let state = guard.get_or_insert_with(Hashes::default);
    let wanted: Vec<PathBuf> = outputs
        .iter()
        .filter(|output| {
            output.hash.is_empty()
                && output.availability == Availability::InRun
                && !output.path.as_os_str().is_empty()
        })
        .map(|output| output.path.clone())
        .filter(|path| !state.known.contains_key(path) && !state.pending.contains(path))
        .collect();
    if wanted.is_empty() {
        return;
    }
    state.pending.extend(wanted.iter().cloned());
    drop(guard);
    let data_dir = data_dir.to_path_buf();
    let wake = ctx.clone();
    let _ = std::thread::Builder::new()
        .name("sample-artifact-hash".into())
        .spawn(move || {
            let library = Library::open(&data_dir).ok();
            for path in wanted {
                let hash = library
                    .as_ref()
                    .and_then(|library| library.artifact_hash(&path))
                    // A file that cannot be read has no hash to show.
                    .unwrap_or_default();
                if let Ok(mut guard) = HASHES.lock() {
                    if let Some(state) = guard.as_mut() {
                        state.pending.remove(&path);
                        state.known.insert(path, hash);
                    }
                }
                wake.request_repaint();
            }
        });
}

fn availability(kept: &KeptArtifact) -> Availability {
    match kept.fate {
        ArtifactFate::Kept => {
            if kept.stored.exists() {
                Availability::Kept(kept.stored.clone(), kept.at_ms)
            } else {
                Availability::Missing
            }
        }
        ArtifactFate::Deleted => Availability::Deleted,
        ArtifactFate::WithVm => Availability::WithVm,
        ArtifactFate::InRecord => Availability::InRecord,
    }
}

/// Add the rows a run's folder and the library hold beyond the three kinds
/// the recorder writes: saved snapshots and files, and what deleted runs
/// left.
pub(in crate::app::samples_page) fn extend(
    out: &mut Vec<Output>,
    entries: &[RunEntry],
    kept: &[KeptArtifact],
) {
    for entry in entries.iter().filter(|entry| entry.folder) {
        for item in antinomie_monitor_core::samples::saved_items(&entry.run.directory) {
            let kind = Kind::of(item.artifact_kind());
            let path = item.file_in(&entry.run.directory).unwrap_or_default();
            let present =
                item.kind == antinomie_monitor_core::samples::SavedKind::Snapshot || path.is_file();
            out.push(Output {
                number: entry.number,
                kind,
                size: if item.size > 0 {
                    Some(item.size)
                } else {
                    std::fs::metadata(&path).ok().map(|meta| meta.len())
                },
                saved_because: item.because(),
                availability: if kind == Kind::Snapshot {
                    Availability::WithVm
                } else if present {
                    Availability::InRun
                } else {
                    Availability::Missing
                },
                state: "Complete".into(),
                hash: item.sha256.clone(),
                name: item.name.clone(),
                run_id: entry.run.id.clone(),
                vm_id: entry.run.vm_id.clone(),
                context: item.context.clone(),
                deleted_ms: None,
                path,
            });
        }
    }
    for row in kept {
        let number = entries
            .iter()
            .find(|entry| entry.run.id == row.run_id && entry.run.vm_id == row.vm_id)
            .map_or(0, |entry| entry.number);
        out.push(Output {
            number,
            kind: Kind::of(row.kind),
            path: row.stored.clone(),
            size: (row.size > 0).then_some(row.size),
            saved_because: row.because.clone(),
            availability: availability(row),
            state: "Complete".into(),
            hash: row.hash.clone(),
            name: row.name.clone(),
            run_id: row.run_id.clone(),
            vm_id: row.vm_id.clone(),
            context: row.context.clone(),
            deleted_ms: None,
        });
        if row.fate == ArtifactFate::Deleted {
            if let Some(last) = out.last_mut() {
                last.deleted_ms = Some(row.at_ms);
            }
        }
    }
}

impl MonitorApp {
    /// Open an artifact in its window: Memory, Core dumps or Network for the
    /// recorder's files, the VM's Snapshots window for a snapshot.
    pub(in crate::app::samples_page) fn open_output(
        &mut self,
        data: &Data,
        number: usize,
        kind: Kind,
    ) {
        let Some(entry) = data.runs.iter().find(|entry| entry.number == number) else {
            return;
        };
        match kind.target() {
            Some(panel) => self.open_sample_run(&entry.run, panel, None),
            None if kind == Kind::Snapshot => {
                self.open_run_snapshots(&entry.run);
            }
            None => {}
        }
    }
}

impl Data {
    pub(in crate::app::samples_page) fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    pub(in crate::app::samples_page) fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}
