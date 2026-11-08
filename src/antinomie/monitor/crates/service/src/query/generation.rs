// SPDX-License-Identifier: GPL-3.0-only
//! The `generation` of a recording (design 5.12.2): a monotonic token for its
//! content, a hash of the sizes and modification times of the files a read
//! depends on. It changes when the recording grows or the pipeline writes its
//! digest; it never changes for a complete recording that is left alone.

use super::cursor::{Generation, stable_hash};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

/// The files of a run folder whose size or time moves the generation.
const WATCHED: [&str; 8] = [
    "run.json",
    "manifest.json",
    "telemetry.raw",
    "terminal.journal",
    "artifacts.json",
    "events.json",
    "triage-digest.json",
    "analysis/report.json",
];

/// The generation of the run folder `directory`. A missing file counts as
/// absent, so a file appearing also changes the token.
pub fn generation_of(directory: &Path) -> Generation {
    let parts: Vec<(&str, i64, i64, i64)> = WATCHED
        .iter()
        .map(|name| match fs::symlink_metadata(directory.join(name)) {
            Ok(meta) if meta.is_file() => {
                (*name, meta.len() as i64, meta.mtime(), meta.mtime_nsec())
            }
            _ => (*name, -1, 0, 0),
        })
        .collect();
    Generation(stable_hash(&parts))
}
