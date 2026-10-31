// SPDX-License-Identifier: GPL-3.0-only
//! Imported archive members must be confined regular files, never devices or FIFOs.
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(crate) fn open_regular(root: &Path, path: &Path) -> io::Result<File> {
    let root = fs::canonicalize(root)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let path = fs::canonicalize(candidate)?;
    if !path.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive member escapes its directory",
        ));
    }
    let before = fs::metadata(&path)?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive member is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    // Linux flags from fcntl-linux.h: reject a replaced leaf symlink, and never
    // block if a regular member is replaced by a FIFO between stat and open.
    #[cfg(target_os = "linux")]
    options.custom_flags(0o400000 | 0o4000);
    let file = options.open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive member changed during open",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_external_symlinks_and_fifo_members_without_blocking() {
        let root = std::env::temp_dir().join(format!("ant-member-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        let external = std::env::temp_dir().join(format!(
            "ant-member-external-{}",
            crate::storage::unique_id()
        ));
        fs::write(&external, b"external").unwrap();
        std::os::unix::fs::symlink(&external, root.join("member.raw")).unwrap();
        assert!(open_regular(&root, Path::new("member.raw")).is_err());
        assert!(
            std::process::Command::new("mkfifo")
                .arg(root.join("fifo.raw"))
                .status()
                .unwrap()
                .success()
        );
        assert!(open_regular(&root, Path::new("fifo.raw")).is_err());
        fs::write(root.join("regular.raw"), b"saved").unwrap();
        assert_eq!(
            open_regular(&root, Path::new("regular.raw"))
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            5
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(external).unwrap();
    }
}
