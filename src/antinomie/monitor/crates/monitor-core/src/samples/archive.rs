// SPDX-License-Identifier: GPL-3.0-only
//! The archives of the library: one AES zip (password `infected`) per sample,
//! named by its SHA-256 and kept in a folder of its first two hex digits
//! (`samples/ab/ab12….zip`), so no folder grows with the library. Nothing is
//! stored unencrypted, and a sample is only decrypted in memory.
use super::{ARCHIVE_PASSWORD, is_sha256, open_sample};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Where the archive of `sha256` lives under the library folder `root`.
pub(super) fn shard_path(root: &Path, sha256: &str) -> Result<PathBuf, String> {
    if !is_sha256(sha256) {
        return Err(format!("not a SHA-256: {sha256:?}"));
    }
    let hash = sha256.to_ascii_lowercase();
    Ok(root.join(&hash[..2]).join(format!("{hash}.zip")))
}

/// Write `bytes` (already hashed to `sha256`) as an archive: owner-only,
/// read back and compared before it takes its name.
pub(super) fn write_bytes(root: &Path, sha256: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let archive = shard_path(root, sha256)?;
    let dir = archive.parent().ok_or("archive has no folder")?;
    crate::storage::private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let partial = archive.with_extension("zip.part");
    let result = (|| {
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&partial)
            .map_err(|e| format!("{}: {e}", partial.display()))?;
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(
                format!("{}.bin", sha256.to_ascii_lowercase()),
                zip::write::SimpleFileOptions::default()
                    .with_aes_encryption(zip::AesMode::Aes256, ARCHIVE_PASSWORD),
            )
            .map_err(|e| format!("sample archive: {e}"))?;
        writer
            .write_all(bytes)
            .map_err(|e| format!("sample archive: {e}"))?;
        writer
            .finish()
            .map_err(|e| format!("sample archive: {e}"))?;
        // Read back as every sample is: the archive must open and match.
        open_sample(&partial, sha256)?;
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        fs::rename(&partial, &archive).map_err(|e| e.to_string())?;
        Ok(archive.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

/// What reading an archive back found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The archive opens and its bytes hash to the sample's SHA-256.
    Matches,
    /// There is no archive.
    Missing,
    /// The archive is there but does not hold the sample.
    Mismatch(String),
}

impl Verification {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Matches)
    }
}

pub(super) fn verify(path: &Path, sha256: &str) -> Verification {
    if !path.is_file() {
        return Verification::Missing;
    }
    match open_sample(path, sha256) {
        Ok(_) => Verification::Matches,
        Err(error) => Verification::Mismatch(error),
    }
}
