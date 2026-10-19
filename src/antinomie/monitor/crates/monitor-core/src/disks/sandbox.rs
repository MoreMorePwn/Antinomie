// SPDX-License-Identifier: MIT
//! The private account file the shared sandbox profile binds over
//! `/etc/passwd`: one unprivileged name, no host account.
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// A private folder (mode 0700, under the system temp folder) holding a
/// one-line `passwd`. Removed when dropped.
pub(crate) struct Account {
    folder: PathBuf,
    passwd: PathBuf,
}

impl Account {
    pub(crate) fn new() -> Result<Self, String> {
        let folder = std::env::temp_dir().join(format!(
            "antinomie-disk-sandbox-{}-{}",
            std::process::id(),
            crate::storage::unique_id()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .map_err(|error| format!("{}: {error}", folder.display()))?;
        let passwd = folder.join("passwd");
        let written = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&passwd)
            .and_then(|mut file| file.write_all(b"nobody:x:65534:65534::/tmp:/bin/false\n"));
        if let Err(error) = written {
            let _ = fs::remove_dir_all(&folder);
            return Err(format!("{}: {error}", passwd.display()));
        }
        Ok(Self { folder, passwd })
    }

    /// The file to bind over `/etc/passwd`.
    pub(crate) fn passwd(&self) -> &Path {
        &self.passwd
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}
