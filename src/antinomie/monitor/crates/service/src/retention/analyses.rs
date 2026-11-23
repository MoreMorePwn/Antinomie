// SPDX-License-Identifier: GPL-3.0-only
//! The static analyses of Auto runs (`<data>/analyses/<id>`, one per tool).
//!
//! The analysis folder of a library sample belongs to no run, so a folder is
//! Auto's only when the run that made it says so: the `analyse` stage writes
//! the run's id into the file [`MARKER`] of each folder. Retention removes the
//! folders of a run with the run's record (and `auto delete --with-recording`
//! with the recording), and the folders whose run record is gone. A folder
//! without a marker (an analysis from the window or `auto analyze`, or one an
//! older version made) is never touched.

use crate::{api::ids::RunId, store::remove::folder_bytes};
use std::{
    io,
    path::{Path, PathBuf},
};

/// The file in an analysis folder that names the Auto run it belongs to.
pub const MARKER: &str = "auto-run";

/// The longest a marker is read.
const MARKER_MAX: u64 = 128;

/// One Auto analysis folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    pub path: PathBuf,
    /// The run (`r_...`) the marker names.
    pub run: String,
    pub bytes: u64,
}

/// The `analyses` folders of a data folder: its own and its lanes'.
pub fn roots(data_dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![data_dir.join("analyses")];
    if let Ok(lanes) = std::fs::read_dir(data_dir.join("lanes")) {
        let mut found: Vec<PathBuf> = lanes
            .flatten()
            .map(|lane| lane.path().join("analyses"))
            .collect();
        found.sort();
        roots.extend(found);
    }
    roots.retain(|root| root.is_dir());
    roots
}

/// Say that the analysis `report_id` under `root` belongs to `run`. A report
/// id that is not one the engine makes is refused.
pub fn mark(root: &Path, report_id: &str, run: &RunId) -> io::Result<()> {
    if report_id.is_empty()
        || !report_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not an analysis id",
        ));
    }
    let folder = root.join(report_id);
    if !std::fs::symlink_metadata(&folder)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the analysis has no folder",
        ));
    }
    std::fs::write(folder.join(MARKER), run.as_str())
}

fn marked_run(folder: &Path) -> Option<String> {
    use std::io::Read;
    let path = folder.join(MARKER);
    if !std::fs::symlink_metadata(&path).ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MARKER_MAX)
        .read_to_string(&mut text)
        .ok()?;
    let text = text.trim();
    RunId::try_from(text.to_owned())
        .ok()
        .map(|_| text.to_owned())
}

/// Every Auto analysis folder under `roots`, with its run and size.
pub fn marked(roots: &[PathBuf]) -> Vec<Folder> {
    let mut out = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            if let Some(run) = marked_run(&path) {
                out.push(Folder {
                    bytes: folder_bytes(&path),
                    path,
                    run,
                });
            }
        }
    }
    out
}

/// The folders of `run`.
pub fn of_run(roots: &[PathBuf], run: &RunId) -> Vec<Folder> {
    marked(roots)
        .into_iter()
        .filter(|folder| folder.run == run.as_str())
        .collect()
}

/// Remove one folder. A link or a file is never followed.
pub fn remove(folder: &Folder) -> io::Result<()> {
    if !std::fs::symlink_metadata(&folder.path)?.is_dir() {
        return Err(io::Error::other("not a folder"));
    }
    std::fs::remove_dir_all(&folder.path)
}
