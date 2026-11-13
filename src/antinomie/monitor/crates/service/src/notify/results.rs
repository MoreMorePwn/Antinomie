// SPDX-License-Identifier: GPL-3.0-only
//! The result drop (design 4.9.3, card P4-4): when `[results] dir` is set,
//! every run that ends leaves `<dir>/<yyyy-mm-dd>/<sha8>-<runid>/` with a
//! copy of `job.json` and its reports, for consumers that poll a folder.
//!
//! A drop is written under a hidden name and renamed into place, so a
//! consumer never sees half of it. Only reports that are not sensitive are
//! copied (never the evidence bundle, a capture, a dump or a core), each read
//! through the same containment check as `artifact.get`, from a no-follow
//! open. A drop that exists is left as it is. By default files and folders are
//! private (0600, 0700): the consumer is the daemon's user, or the
//! administrator gives it access to `dir` itself. `[results] mode = "group"`
//! makes them 0640 and 0750 so the daemon's group can read them; nothing is
//! ever writable by others, and the umask cannot widen either mode.

use super::calendar::date_of;
use crate::{
    api::{artifact::ArtifactKind, run::Run},
    config::service::ResultsMode,
    daemon::artifacts::resolve,
    store::{Store, mirror::write_private},
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Most bytes one drop copies (reports are small; this is a safety bound).
pub const MAX_DROP_BYTES: u64 = 256 << 20;

/// Make a folder with exactly `mode` (the umask is not allowed to narrow a
/// group-readable folder into one the consumer cannot enter).
fn made_dir(path: &Path, mode: u32) -> io::Result<()> {
    fs::DirBuilder::new().mode(mode).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// A folder that exists as a plain folder (a link is refused), made if it is
/// missing.
fn plain_dir(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a plain folder (a link or a file)",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(mode)
                    .create(parent)?;
            }
            made_dir(path, mode)
        }
        Err(error) => Err(error),
    }
}

fn report_kind(kind: ArtifactKind) -> bool {
    matches!(
        kind,
        ArtifactKind::ReportHtml
            | ArtifactKind::ReportPdf
            | ArtifactKind::ReportJson
            | ArtifactKind::ReportMisp
            | ArtifactKind::ReportStix
            | ArtifactKind::ReportMd
    )
}

/// A file name that stays inside one folder.
fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    if cleaned.is_empty() || cleaned.starts_with('.') {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

/// The name of a drop folder: `<sha8>-<runid>`.
pub fn drop_name(job: &Run) -> String {
    let sha8 = job
        .sample
        .as_ref()
        .map_or("nosample", |s| &s.sha256.as_str()[..8]);
    format!("{sha8}-{}", job.id)
}

/// Write the drop of `job`. Returns its folder.
pub fn write(
    store: &Store,
    job: &Run,
    root: &Path,
    mode: ResultsMode,
    now_ms: u64,
) -> Result<PathBuf, String> {
    plain_dir(root, mode.dir_mode()).map_err(|e| format!("{}: {e}", root.display()))?;
    let day = root.join(date_of(job.finished_ms.unwrap_or(now_ms)));
    plain_dir(&day, mode.dir_mode()).map_err(|e| format!("{}: {e}", day.display()))?;
    let name = drop_name(job);
    let target = day.join(&name);
    if fs::symlink_metadata(&target).is_ok() {
        return Ok(target);
    }
    let staging = day.join(format!(".{name}.partial"));
    if let Ok(meta) = fs::symlink_metadata(&staging)
        && meta.is_dir()
    {
        // Left by a drop that was cut short: ours, by its hidden name.
        let _ = fs::remove_dir_all(&staging);
    }
    made_dir(&staging, mode.dir_mode()).map_err(|e| format!("{}: {e}", staging.display()))?;
    let outcome = fill(store, job, &staging, mode);
    if let Err(error) = outcome {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    fs::rename(&staging, &target).map_err(|e| {
        let _ = fs::remove_dir_all(&staging);
        format!("{}: {e}", target.display())
    })?;
    Ok(target)
}

fn fill(store: &Store, job: &Run, staging: &Path, mode: ResultsMode) -> Result<(), String> {
    let job_dir = store.job_dir(&job.id);
    let json = serde_json::to_vec_pretty(job).map_err(|e| e.to_string())?;
    let job_json = staging.join("job.json");
    write_private(&job_json, &json).map_err(|e| format!("job.json: {e}"))?;
    fs::set_permissions(&job_json, fs::Permissions::from_mode(mode.file_mode()))
        .map_err(|e| format!("job.json: {e}"))?;
    let mut copied = json.len() as u64;
    for artifact in &job.artifacts {
        if !report_kind(artifact.kind) || artifact.sensitive {
            continue;
        }
        let (_, location) = store
            .artifact(&artifact.id)
            .map_err(|e| format!("artifact {}: {}", artifact.id, e.message))?;
        let source = resolve(&job_dir, &location)
            .map_err(|e| format!("artifact {}: {}", artifact.name, e.message))?;
        let mut input = fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&source)
            .map_err(|e| format!("artifact {}: {e}", artifact.name))?;
        let meta = input.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err(format!("artifact {} is not a file", artifact.name));
        }
        copied += meta.len();
        if copied > MAX_DROP_BYTES {
            return Err("the reports are larger than a drop may hold".into());
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode.file_mode())
            .open(staging.join(safe_name(&artifact.name)))
            .map_err(|e| format!("artifact {}: {e}", artifact.name))?;
        output
            .set_permissions(fs::Permissions::from_mode(mode.file_mode()))
            .map_err(|e| format!("artifact {}: {e}", artifact.name))?;
        copy_exact(&mut input, &mut output, meta.len())
            .map_err(|e| format!("artifact {}: {e}", artifact.name))?;
        output.sync_all().map_err(|e| e.to_string())?;
    }
    File::open(staging)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| e.to_string())
}

fn copy_exact(input: &mut impl Read, output: &mut impl Write, limit: u64) -> io::Result<()> {
    io::copy(&mut input.take(limit), output).map(|_| ())
}
