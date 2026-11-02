// SPDX-License-Identifier: GPL-3.0-only
//! Export a deleted file's bytes as they were just before the delete.
//!
//! The recording holds the writes the run made to the file and the guest took
//! the file's SHA-256 just before it unlinked it. The bytes are rebuilt as of
//! the last moment before the delete, the rebuilt content is hashed and the
//! hash is compared with the guest's: a match means the export is exactly the
//! file the guest deleted. The result is saved with a record of that check and
//! noted in the custody log of the sample the run belongs to.
use super::{save_name, FileActivity, Open, Pending};
use crate::widgets::{self, Tone};
use antinomie_monitor_core::file_reconstruct::{Incomplete, Reconstruction};
use antinomie_monitor_core::samples::CustodyEvent;
use eframe::egui::{self, RichText};
use std::path::{Path, PathBuf};

/// The folder of the app's data, which holds the sample library. The Files
/// tab leaves it in the context for the window.
pub(in crate::triage) const DATA_DIR: &str = "triage-reconstruct-data-dir";

/// What the export needs of the file's moment of deletion.
#[derive(Clone, Debug)]
pub(super) struct Prepared {
    /// Calls applied by the last moment before the delete.
    pub position: usize,
    /// Guest time of the delete.
    pub deleted_ns: Option<u64>,
    /// The size of the rebuilt file (the highest offset reached when unknown).
    pub size: u64,
    pub size_known: bool,
    /// Bytes that have no value at that point.
    pub missing: u64,
    /// The SHA-256 the guest took just before the delete, when it took one.
    pub guest: Option<String>,
    /// Why there is none.
    pub no_guest: String,
}

impl Prepared {
    pub(super) fn complete(&self) -> bool {
        self.size_known && self.missing == 0
    }
}

/// How the rebuilt bytes compare with what the guest hashed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Complete, and the hash is the guest's.
    Verified,
    /// Complete, and the hash is not the guest's.
    Differs,
    /// Complete, and the guest took no hash to compare with.
    NoGuestHash(String),
    /// Bytes are missing, so there is nothing to hash.
    Partial(u64),
}

impl Verdict {
    pub(super) fn text(&self) -> String {
        match self {
            Self::Verified => {
                "verified: the SHA-256 of the rebuilt bytes is the one the guest took just before the delete".into()
            }
            Self::Differs => {
                "does not match the SHA-256 the guest took just before the delete (the recording misses a change)".into()
            }
            Self::NoGuestHash(why) => format!("not compared: {why}"),
            Self::Partial(missing) => format!("partial: {missing} bytes unknown"),
        }
    }

    fn key(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Differs => "differs",
            Self::NoGuestHash(_) => "not_compared",
            Self::Partial(_) => "partial",
        }
    }
}

/// What the custody log needs to be written to.
#[derive(Clone)]
pub(super) struct Custody {
    pub data_dir: PathBuf,
    pub sample: String,
    pub run: String,
}

impl Custody {
    /// Where this run's sample is kept, when the app has set it for the frame.
    pub(super) fn of(ctx: &egui::Context) -> Option<Self> {
        let data_dir = ctx.data(|data| data.get_temp::<PathBuf>(egui::Id::new(DATA_DIR)))?;
        let run = crate::query::NoteRun::get(ctx)?;
        Some(Self {
            data_dir,
            sample: run.sample?,
            run: run.run_id,
        })
    }
}

/// The file's state at the last moment before its delete.
pub(super) fn prepare(file: &FileActivity, map: &Reconstruction) -> Prepared {
    let note = file
        .hashes
        .iter()
        .rev()
        .find(|note| note.moment == "before delete");
    let deleted_ns = note.map(|note| note.time).or_else(|| {
        file.events
            .iter()
            .rev()
            .find(|event| event.kind == super::super::Kind::Delete && event.success != Some(false))
            .map(|event| event.time)
    });
    let position = deleted_ns.map_or(map.steps().len(), |time| map.steps_until(time));
    let mut at = map.clone();
    at.goto(position);
    let (guest, no_guest) = match note {
        Some(note) => match &note.sha256 {
            Some(hex) if !note.changed => (Some(hex.clone()), String::new()),
            Some(_) => (
                None,
                "the file changed while the guest read it, so its hash may not match".into(),
            ),
            None => (
                None,
                note.skipped
                    .clone()
                    .unwrap_or_else(|| "the guest took no hash".into()),
            ),
        },
        None => (None, "the guest took no hash just before the delete".into()),
    };
    Prepared {
        position,
        deleted_ns,
        size: at.size(),
        size_known: at.size_known(),
        missing: at.counts().missing(),
        guest,
        no_guest,
    }
}

/// Rebuild, hash, compare and save. The text is what the window shows.
fn export(
    mut map: Reconstruction,
    prepared: Prepared,
    path: String,
    first_ns: u64,
    directory: PathBuf,
    custody: Option<Custody>,
) -> Result<String, String> {
    map.goto(prepared.position);
    let verdict = if !prepared.complete() {
        Verdict::Partial(prepared.missing)
    } else {
        match (map.sha256(), &prepared.guest) {
            (Ok(hex), Some(guest)) if hex.eq_ignore_ascii_case(guest) => Verdict::Verified,
            (Ok(_), Some(_)) => Verdict::Differs,
            (Ok(_), None) => Verdict::NoGuestHash(prepared.no_guest.clone()),
            (Err(Incomplete::Missing(count)), _) => Verdict::Partial(count),
            (Err(Incomplete::SizeUnknown), _) => Verdict::Partial(prepared.missing),
            (Err(Incomplete::Unreadable), _) => {
                Verdict::NoGuestHash("some bytes could not be read back".into())
            }
        }
    };
    let hex = map.sha256().ok();
    let target = directory.join("reconstructed");
    std::fs::create_dir_all(&target)
        .map_err(|error| format!("Could not create {}: {error}", target.display()))?;
    let name = format!("{}-before-deletion", save_name(&path, first_ns));
    let (data, mask, record) = (
        target.join(format!("{name}.bin")),
        target.join(format!("{name}.mask")),
        target.join(format!("{name}.json")),
    );
    let create = |path: &Path| {
        std::fs::File::create(path)
            .map(std::io::BufWriter::new)
            .map_err(|error| format!("Could not write {}: {error}", path.display()))
    };
    let mut data_out = create(&data)?;
    let mut mask_out = match verdict {
        Verdict::Partial(_) => Some(create(&mask)?),
        _ => {
            let _ = std::fs::remove_file(&mask);
            None
        }
    };
    let saved = map
        .save(
            &mut data_out,
            mask_out.as_mut().map(|out| out as &mut dyn std::io::Write),
        )
        .map_err(|error| format!("Could not write the export: {error}"))?;
    use std::io::Write;
    data_out
        .flush()
        .and(mask_out.as_mut().map_or(Ok(()), |out| out.flush()))
        .map_err(|error| format!("Could not write the export: {error}"))?;
    let summary = serde_json::json!({
        "file": path,
        "as_of": "the last moment before the file was deleted",
        "deleted_guest_ns": prepared.deleted_ns,
        "bytes": saved.bytes,
        "unknown_bytes": saved.filled,
        "sha256": hex,
        "guest_sha256_before_delete": prepared.guest,
        "result": verdict.key(),
        "note": verdict.text(),
        "mask": mask_out.is_some().then(|| format!("{name}.mask")),
    });
    std::fs::write(
        &record,
        serde_json::to_vec_pretty(&summary).unwrap_or_default(),
    )
    .map_err(|error| format!("Could not write {}: {error}", record.display()))?;
    let custody_note = match custody {
        Some(custody) => match note_custody(&custody, &path, saved.bytes, hex.as_deref(), &verdict)
        {
            Ok(()) => " Noted in the sample's custody log.".to_owned(),
            Err(error) => format!(" The custody log was not written: {error}."),
        },
        None => " This run has no library sample, so no custody entry was made.".to_owned(),
    };
    Ok(format!(
        "Saved {} B to {} ({}). The check is in {}.{custody_note}",
        saved.bytes,
        data.display(),
        verdict.text(),
        record.display(),
    ))
}

/// The custody entry: what was exported and whether it was verified.
fn note_custody(
    custody: &Custody,
    path: &str,
    bytes: u64,
    sha256: Option<&str>,
    verdict: &Verdict,
) -> Result<(), String> {
    let library = antinomie_monitor_core::samples::Library::open(&custody.data_dir)?;
    let (record, _) = library.custody_record(&custody.sample)?;
    let head = record["status"]["head"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    library.record_event(
        &custody.sample,
        "analyst",
        CustodyEvent::Exported {
            format: format!(
                "bytes of {path} as before deletion, run {} ({bytes} B, SHA-256 {}; {})",
                custody.run,
                sha256.unwrap_or("none"),
                verdict.text()
            ),
            signed: "unsigned".into(),
            head,
        },
    )
}

impl Open {
    /// The file's state at its delete, worked out once.
    fn deletion(&mut self, file: &FileActivity) -> &Prepared {
        let map = &self.map;
        self.before.get_or_insert_with(|| prepare(file, map))
    }

    /// Export bytes (as before deletion), for a file the run deleted.
    pub(super) fn before_deletion(
        &mut self,
        ui: &mut egui::Ui,
        file: &FileActivity,
        directory: Option<&Path>,
    ) {
        let prepared = self.deletion(file).clone();
        ui.add_space(6.0);
        ui.label(RichText::new("Before deletion").strong());
        if prepared.complete() {
            widgets::chip(ui, "complete", Tone::Good);
        } else {
            widgets::chip(
                ui,
                &format!("partial: {} bytes unknown", prepared.missing),
                Tone::Warn,
            );
        }
        ui.weak(format!(
            "{} B{}",
            prepared.size,
            if prepared.size_known {
                ""
            } else {
                " at least (the size is not known)"
            }
        ));
        match &prepared.guest {
            Some(hex) => {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Guest SHA-256 before the delete\n{hex}"))
                            .monospace()
                            .small(),
                    )
                    .wrap(),
                );
            }
            None => {
                ui.weak(format!(
                    "No guest hash to compare with: {}.",
                    prepared.no_guest
                ));
            }
        }
        let busy = self.saving.is_some();
        let can = directory.is_some() && !busy;
        let button = |label: &str| egui::Button::new(label.to_owned());
        let (label, hover) = if prepared.complete() {
            (
                "Export bytes (as before deletion)",
                "Rebuild the file as of the last moment before the delete, compare it with the guest's hash and save it",
            )
        } else {
            (
                "Export known bytes (partial)",
                "Save what the recording shows; bytes it never saw are 00, marked in a .mask file next to it",
            )
        };
        if ui
            .add_enabled(can, button(label))
            .on_hover_text(hover)
            .clicked()
        {
            if let Some(directory) = directory {
                let (ctx, map) = (ui.ctx().clone(), self.map.clone());
                let custody = Custody::of(&ctx);
                let (path, first) = (file.path.clone(), file.first_ns);
                let directory = directory.to_path_buf();
                self.saving = Some(Pending::spawn(&ctx, move || {
                    export(map, prepared, path, first, directory, custody)
                }));
            }
        }
        if directory.is_none() {
            ui.weak("Saving needs a recording on disk.");
        }
        if self.saving.is_some() {
            ui.weak("Rebuilding and saving…");
        }
    }
}
