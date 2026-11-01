// SPDX-License-Identifier: GPL-3.0-only
//! Imported archive members must be confined regular files, never devices or FIFOs.
//!
//! Reading a recording opens its members once per packet field (ANT-T0203: a
//! whole-run export spent 83 % of its time here), so the confinement check is
//! made on the opened file itself: the path the kernel reports for the open
//! descriptor must lie under the root, whose resolved path is remembered for
//! as long as the root still names the same directory. A member that is a
//! symlink, or a system without `/proc/self/fd`, takes the full check of each
//! path component as before.
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Roots whose resolved path is remembered: the given path, the directory it
/// named (device, inode) and its resolved path.
type Resolved = Vec<(PathBuf, (u64, u64), PathBuf)>;
static RESOLVED: Mutex<Resolved> = Mutex::new(Vec::new());
/// Roots remembered at once; the least recently used is forgotten.
const RESOLVED_ROOTS: usize = 16;
/// Linux open flags (fcntl-linux.h): no leaf symlink, never block on a FIFO.
const NOFOLLOW_NONBLOCK: i32 = 0o400000 | 0o4000;

/// The resolved path of directory `root`, as `fs::canonicalize` gives it.
/// Remembered while `root` names the same directory; `fresh` resolves again.
pub(crate) fn canonical_dir(root: &Path, fresh: bool) -> io::Result<PathBuf> {
    let metadata = fs::metadata(root)?;
    let identity = (metadata.dev(), metadata.ino());
    let mut resolved = RESOLVED.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(index) = resolved.iter().position(|(path, _, _)| path == root) {
        let entry = resolved.remove(index);
        if !fresh && entry.1 == identity {
            let canonical = entry.2.clone();
            resolved.push(entry);
            return Ok(canonical);
        }
    }
    drop(resolved);
    let canonical = fs::canonicalize(root)?;
    let mut resolved = RESOLVED.lock().unwrap_or_else(|error| error.into_inner());
    resolved.retain(|(path, _, _)| path != root);
    if resolved.len() >= RESOLVED_ROOTS {
        resolved.remove(0);
    }
    resolved.push((root.to_path_buf(), identity, canonical.clone()));
    Ok(canonical)
}

pub(crate) fn open_regular(root: &Path, path: &Path) -> io::Result<File> {
    match open_confined(root, path) {
        Some(result) => result,
        None => open_checked(root, path),
    }
}

/// Open the member, then check the file that was opened: a regular file whose
/// path lies under the root. `None` asks for the full check instead (the
/// member is a symlink, or the descriptor's path cannot be read).
fn open_confined(root: &Path, path: &Path) -> Option<io::Result<File>> {
    let canonical = match canonical_dir(root, false) {
        Ok(canonical) => canonical,
        Err(error) => return Some(Err(error)),
    };
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        canonical.join(path)
    };
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(NOFOLLOW_NONBLOCK);
    let file = match options.open(&candidate) {
        Ok(file) => file,
        // ELOOP: the member itself is a symlink.
        Err(error) if error.raw_os_error() == Some(40) => return None,
        Err(error) => return Some(Err(error)),
    };
    let opened = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
    let inside = opened.starts_with(&canonical)
        || canonical_dir(root, true).is_ok_and(|fresh| opened.starts_with(fresh));
    if !inside {
        return Some(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive member escapes its directory",
        )));
    }
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => Some(Ok(file)),
        Ok(_) => Some(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive member is not a regular file",
        ))),
        Err(error) => Some(Err(error)),
    }
}

/// Resolve every component of the member's path, then open it and check that
/// it is still the file that was resolved.
fn open_checked(root: &Path, path: &Path) -> io::Result<File> {
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
    options.custom_flags(NOFOLLOW_NONBLOCK);
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
        // A symlink to a member inside the root is followed, as before.
        fs::write(root.join("inner.raw"), b"inner").unwrap();
        std::os::unix::fs::symlink(root.join("inner.raw"), root.join("link.raw")).unwrap();
        assert_eq!(
            open_regular(&root, Path::new("link.raw"))
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            5
        );
        // So is a symlinked directory inside it; one leading out is refused.
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/deep.raw"), b"deep").unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("alias")).unwrap();
        assert!(open_regular(&root, Path::new("alias/deep.raw")).is_ok());
        std::os::unix::fs::symlink(std::env::temp_dir(), root.join("out")).unwrap();
        let outside = external.file_name().unwrap();
        assert!(open_regular(&root, &Path::new("out").join(outside)).is_err());
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

    #[test]
    fn a_remembered_root_follows_the_directory_its_path_names() {
        let base = std::env::temp_dir().join(format!("ant-root-{}", crate::storage::unique_id()));
        let (first, second) = (base.join("first"), base.join("second"));
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("member.raw"), b"one").unwrap();
        fs::write(second.join("member.raw"), b"second").unwrap();
        let root = base.join("root");
        std::os::unix::fs::symlink(&first, &root).unwrap();
        let len = |root: &Path| {
            open_regular(root, Path::new("member.raw"))
                .unwrap()
                .metadata()
                .unwrap()
                .len()
        };
        assert_eq!(len(&root), 3);
        // The same path now names another directory: it is resolved again.
        fs::remove_file(&root).unwrap();
        std::os::unix::fs::symlink(&second, &root).unwrap();
        assert_eq!(len(&root), 6);
        assert_eq!(
            canonical_dir(&root, false).unwrap(),
            fs::canonicalize(&second).unwrap()
        );
        fs::remove_dir_all(base).unwrap();
    }
}
