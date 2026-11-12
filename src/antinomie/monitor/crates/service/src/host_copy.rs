// SPDX-License-Identifier: GPL-3.0-only
//! The library's copy of a sample as a run's host copy (ANT-T0449).
//!
//! The library keeps a sample only as an encrypted archive. The engine's host
//! copy (`ExecRequest::host_copy`) is a plain file it reads once, when the
//! launch is acknowledged: it stages it into the run's specimen store, and the
//! guest's digest vouches for it (ANT-T0344), and a refused launch is analysed
//! from it. A [`StagedCopy`] decrypts the archive (read-only) into a private
//! file for that moment and removes the file when it is dropped, so no copy is
//! left behind; a copy a killed process left is removed by the next staging
//! ([`sweep`]).
use antinomie_monitor_core::samples::{archive_path, open_sample};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// The folder (inside the data directory) the staged files live in.
pub const DIR: &str = "host-copy";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A plain file holding a library sample, removed on drop.
#[derive(Debug)]
pub struct StagedCopy {
    path: PathBuf,
}

impl StagedCopy {
    /// Decrypt the library's archive of `sha256` into a private file. `None`
    /// when the library has no readable archive for it (the run then goes
    /// ahead without a host copy, as before).
    pub fn stage(data_dir: &Path, sha256: &str) -> Option<Self> {
        let archive = archive_path(data_dir, sha256).ok()?;
        let bytes = open_sample(&archive, sha256).ok()?;
        let dir = data_dir.join(DIR);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .ok()?;
        sweep(&dir);
        let name = format!(
            "{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            sha256.get(..16).unwrap_or(sha256)
        );
        let path = dir.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        let copy = Self { path };
        // A failed write drops `copy`, which removes the partial file.
        file.write_all(&bytes).ok()?;
        file.sync_all().ok()?;
        Some(copy)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Remove the copies in `dir` that a process which is gone left behind (one
/// killed during a launch: SIGKILL, the OOM killer, a power loss), so a
/// decrypted sample does not stay on the host's disk. A copy is named
/// `<pid>-<n>-<sha16>`; one whose process still runs (or whose name is not of
/// that form) is left alone. Returns how many were removed.
pub fn sweep(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.split('-').next())
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() || Path::new("/proc").join(pid.to_string()).exists() {
            continue;
        }
        // Plain files only, never through a link.
        if entry.file_type().is_ok_and(|kind| kind.is_file())
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

impl Drop for StagedCopy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_left_by_a_process_that_is_gone_is_swept() {
        let dir = std::env::temp_dir().join(format!("ant-hostcopy-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Above any pid_max: no such process.
        let stale = dir.join(format!("4294967295-0-{}", "a".repeat(16)));
        let mine = dir.join(format!("{}-7-{}", std::process::id(), "b".repeat(16)));
        let other = dir.join("notes.txt");
        for path in [&stale, &mine, &other] {
            fs::write(path, b"x").unwrap();
        }
        assert_eq!(sweep(&dir), 1);
        assert!(!stale.exists());
        assert!(mine.exists() && other.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sample_the_library_lacks_stages_nothing() {
        let root = std::env::temp_dir().join(format!("ant-hostcopy-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        assert!(StagedCopy::stage(&root, &"a".repeat(64)).is_none());
        assert!(!root.join(DIR).exists() || fs::read_dir(root.join(DIR)).unwrap().count() == 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_library_sample_is_staged_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("ant-hostcopy-lib-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let bytes = b"#!/bin/sh\necho hi\n".to_vec();
        let mut library = antinomie_monitor_core::samples::Library::open(&root).unwrap();
        let added = library
            .add_bytes(
                &bytes,
                antinomie_monitor_core::samples::NewSample::default(),
            )
            .unwrap();
        let archive = archive_path(&root, &added.sha256).unwrap();
        let archive_before = fs::read(&archive).unwrap();
        let path;
        {
            let copy = StagedCopy::stage(&root, &added.sha256).expect("staged");
            path = copy.path().to_owned();
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!path.exists(), "no copy is left behind");
        assert_eq!(
            fs::read(&archive).unwrap(),
            archive_before,
            "the library file is untouched"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
