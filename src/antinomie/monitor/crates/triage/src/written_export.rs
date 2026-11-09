// SPDX-License-Identifier: GPL-3.0-only
//! Keeps the executables and libraries a finished run wrote, beside the run,
//! so the YARA scan can read them. Each is rebuilt from the run's recorded
//! writes ([`antinomie_monitor_core::file_reconstruct`]); only a file whose
//! every byte is known is kept, under the name of its SHA-256, and one that
//! could not be rebuilt whole is listed with the reason. See
//! `antinomie_monitor_core::analysis::detection::written`.
use crate::file_activity::{start_of, Activity, FileActivity};
use antinomie_monitor_core::{
    analysis::detection::written::{
        self, Entry, Index, Skip, MAX_FILES, MAX_FILE_SIZE, MAX_TOTAL_SIZE,
    },
    file_reconstruct::Reconstruction,
};
use std::path::Path;

/// Files looked at; a run that touched more is cut here, and the index says so.
const EXAMINED: usize = 4096;
/// Skipped rows kept in the index.
const SKIPPED: usize = 64;

/// Rebuild the written ELF files of `activity` and save them under `run`'s
/// [`written::FOLDER`]. Returns the index it saved (also when nothing was
/// kept, so a scan can tell "none" from "not read yet").
pub fn export(run: &Path, activity: &Activity, partial: bool) -> Result<Index, String> {
    let index = build(activity, partial, |sha256, bytes| {
        let folder = run.join(written::FOLDER);
        std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
        let target = folder.join(sha256);
        if target.is_file() {
            return Ok(());
        }
        let partial = folder.join(format!("{sha256}.part"));
        std::fs::write(&partial, bytes).map_err(|error| error.to_string())?;
        std::fs::rename(&partial, &target).map_err(|error| error.to_string())
    })?;
    let folder = run.join(written::FOLDER);
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    let file = folder.join(written::INDEX);
    let encoded = serde_json::to_vec_pretty(&index).map_err(|error| error.to_string())?;
    if std::fs::read(&file).ok().as_deref() != Some(encoded.as_slice()) {
        let partial = folder.join("index.json.part");
        std::fs::write(&partial, &encoded).map_err(|error| error.to_string())?;
        std::fs::rename(&partial, &file).map_err(|error| error.to_string())?;
    }
    Ok(index)
}

/// The index for `activity`, handing each kept file to `keep(sha256, bytes)`.
pub fn build(
    activity: &Activity,
    partial: bool,
    mut keep: impl FnMut(&str, &[u8]) -> Result<(), String>,
) -> Result<Index, String> {
    let mut index = Index::default();
    let mut total = 0u64;
    let skip = |index: &mut Index, path: &str, reason: String| {
        if index.skipped.len() < SKIPPED {
            index.skipped.push(Skip {
                path: path.to_owned(),
                reason,
            });
        }
    };
    let mut examined = 0usize;
    for file in activity.files.iter().filter(|file| candidate(file)) {
        examined += 1;
        if examined > EXAMINED {
            skip(
                &mut index,
                "(more files)",
                format!("the run changed more than {EXAMINED} files; the rest were not examined"),
            );
            break;
        }
        let mut map = Reconstruction::new(start_of(file), &file.timeline);
        map.goto(file.timeline.steps().len());
        let Ok(head) = map.bytes(0, 20) else {
            continue;
        };
        let Some(kind) = written::elf_kind(&head) else {
            continue;
        };
        if index.files.len() >= MAX_FILES {
            skip(
                &mut index,
                &file.path,
                format!("only the first {MAX_FILES} written programs are kept"),
            );
            continue;
        }
        let size = map.size();
        if size > MAX_FILE_SIZE || total.saturating_add(size) > MAX_TOTAL_SIZE {
            skip(
                &mut index,
                &file.path,
                "over the size budget for written files".into(),
            );
            continue;
        }
        let mut bytes = Vec::with_capacity(size as usize);
        let saved = match map.save(&mut bytes, None) {
            Ok(saved) => saved,
            Err(error) => {
                skip(
                    &mut index,
                    &file.path,
                    format!("could not be rebuilt: {error}"),
                );
                continue;
            }
        };
        if !map.size_known() || saved.filled > 0 || saved.unreadable > 0 {
            let (_, unseen) = map.gaps();
            skip(
                &mut index,
                &file.path,
                format!(
                    "not rebuilt whole: {} bytes were not captured or not seen ({} never seen)",
                    saved.filled + saved.unreadable,
                    unseen
                ),
            );
            continue;
        }
        let sha256 = antinomie_monitor_core::file_reconstruct::sha256_hex(&bytes);
        // The guest hashed the file when it closed it: a rebuild that differs
        // is not the file the guest had, so it is not scanned as that file.
        let guest = file
            .hashes
            .iter()
            .rev()
            .find_map(|note| note.sha256.as_deref().filter(|_| !note.changed));
        // A run index that is partial (calls lost) may have missed a later
        // write; only the guest's own hash can vouch for the rebuilt bytes.
        if partial && guest.is_none() {
            skip(
                &mut index,
                &file.path,
                "the run's index is partial and the guest took no hash of this file to check the rebuilt bytes".into(),
            );
            continue;
        }
        if let Some(guest) = guest
            && !guest.eq_ignore_ascii_case(&sha256)
        {
            skip(
                &mut index,
                &file.path,
                "the rebuilt bytes differ from the hash the guest took, so they were not scanned"
                    .into(),
            );
            continue;
        }
        keep(&sha256, &bytes)?;
        total += size;
        index.files.push(Entry {
            path: file.path.clone(),
            file: sha256.clone(),
            sha256,
            size,
            kind: kind.into(),
        });
    }
    Ok(index)
}

/// A file the run changed under a real path.
fn candidate(file: &FileActivity) -> bool {
    file.path_known
        && file.path.starts_with('/')
        && !file.standard_io
        && !file.failed_only
        && !file.timeline.is_empty()
        && (file.created || file.changed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{
        file_reconstruct::{Action, Step, Timeline},
        file_writes::{Extent, Gap, Piece, Source, Writes},
    };

    fn written(path: &str, steps: Vec<Action>) -> FileActivity {
        let mut timeline = Timeline::default();
        for (at, action) in steps.into_iter().enumerate() {
            timeline.push(Step {
                time_ns: at as u64 + 1,
                event: None,
                order: None,
                action,
            });
        }
        FileActivity {
            path: path.into(),
            path_known: true,
            names: vec![],
            identity: None,
            events: vec![],
            omitted: 0,
            first_ns: 1,
            last_ns: 2,
            standard_io: false,
            created: true,
            deleted: false,
            failed_only: false,
            contents: Default::default(),
            hashes: vec![],
            writes: Writes::default(),
            timeline,
            first_segment: 0,
            last_segment: 0,
            earlier: None,
            start_hash: None,
        }
    }

    fn kept(bytes: &[u8]) -> Action {
        Action::Write(vec![Extent {
            offset: 0,
            len: bytes.len() as u64,
            piece: Piece::Kept(Source::Inline(bytes.to_vec())),
        }])
    }

    fn elf(kind: u8, tail: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[5] = 1;
        bytes[16] = kind;
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn an_activity_with_no_files_gives_an_empty_index() {
        let index = build(&Activity::default(), false, |_, _| unreachable!()).unwrap();
        assert!(index.files.is_empty() && index.skipped.is_empty());
    }

    #[test]
    fn whole_elf_files_are_kept_by_hash_and_everything_else_is_left_alone() {
        let library = elf(3, b"LIBRARY_MARKER");
        let activity = Activity {
            files: vec![
                written("/lib/libntpx/.backup_ld.so", vec![kept(&library)]),
                written("/tmp/notes.txt", vec![kept(b"plain text, not a program")]),
                // Half of the file was written without a captured payload.
                written(
                    "/tmp/half.so",
                    vec![
                        kept(&elf(3, b"")),
                        Action::Write(vec![Extent {
                            offset: 20,
                            len: 100,
                            piece: Piece::NotCaptured(Gap::NotRecorded),
                        }]),
                    ],
                ),
            ],
            ..Activity::default()
        };
        let mut kept_files = Vec::new();
        let index = build(&activity, false, |sha, bytes| {
            kept_files.push((sha.to_owned(), bytes.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(index.files.len(), 1, "{index:?}");
        let entry = &index.files[0];
        assert_eq!(entry.path, "/lib/libntpx/.backup_ld.so");
        assert_eq!(entry.kind, "library");
        assert_eq!(entry.file, entry.sha256);
        assert_eq!(
            entry.sha256,
            antinomie_monitor_core::file_reconstruct::sha256_hex(&library)
        );
        assert_eq!(kept_files, [(entry.sha256.clone(), library)]);
        assert_eq!(index.skipped.len(), 1);
        assert_eq!(index.skipped[0].path, "/tmp/half.so");
        assert!(
            index.skipped[0].reason.contains("not rebuilt whole"),
            "{index:?}"
        );
    }

    #[test]
    fn a_partial_run_index_keeps_a_file_only_when_the_guest_hash_vouches_for_it() {
        let library = elf(3, b"LIBRARY_MARKER");
        let sha = antinomie_monitor_core::file_reconstruct::sha256_hex(&library);
        let mut vouched = written("/tmp/vouched.so", vec![kept(&library)]);
        vouched.hashes.push(crate::file_activity::HashNote {
            time: 5,
            moment: "closed after write",
            sha256: Some(sha.clone()),
            changed: false,
            skipped: None,
        });
        let mut altered = written("/tmp/altered.so", vec![kept(&library)]);
        altered.hashes.push(crate::file_activity::HashNote {
            time: 5,
            moment: "closed after write",
            sha256: Some("0".repeat(64)),
            changed: false,
            skipped: None,
        });
        let activity = Activity {
            files: vec![
                vouched,
                altered,
                written("/tmp/unchecked.so", vec![kept(&library)]),
            ],
            ..Activity::default()
        };
        let index = build(&activity, true, |_, _| Ok(())).unwrap();
        let kept_paths: Vec<_> = index
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        assert_eq!(kept_paths, ["/tmp/vouched.so"]);
        assert_eq!(index.files[0].sha256, sha);
        assert_eq!(index.skipped.len(), 2, "{index:?}");
        assert!(index
            .skipped
            .iter()
            .any(|skip| skip.path == "/tmp/unchecked.so" && skip.reason.contains("partial")));
        assert!(index
            .skipped
            .iter()
            .any(|skip| skip.path == "/tmp/altered.so" && skip.reason.contains("differ")));
        // A whole index needs no vouching.
        assert_eq!(
            build(&activity, false, |_, _| Ok(())).unwrap().files.len(),
            2
        );
    }

    #[test]
    fn export_writes_the_files_and_an_index_the_yara_scan_reads() {
        let directory = std::env::temp_dir().join(format!(
            "ant-written-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let program = elf(2, b"dropped");
        let activity = Activity {
            files: vec![written("/tmp/dropper", vec![kept(&program)])],
            ..Activity::default()
        };
        let index = export(&directory, &activity, false).unwrap();
        assert_eq!(index.files.len(), 1);
        let read = written::read(&directory).unwrap();
        assert_eq!(read, index);
        let blob = directory.join("written").join(&read.files[0].file);
        assert_eq!(std::fs::read(blob).unwrap(), program);
        // Writing again changes nothing.
        assert_eq!(export(&directory, &activity, false).unwrap(), index);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
