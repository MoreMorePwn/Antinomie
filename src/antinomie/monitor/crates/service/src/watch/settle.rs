// SPDX-License-Identifier: GPL-3.0-only
//! What happens to a watched file once intake has dealt with it (design
//! 4.2.1 "Failure", `delete_after`), and the record that keeps a `keep`ed
//! file from being taken again.
//!
//! Every step works relative to the folder's own descriptor and first
//! checks that the name still leads to the file that was read: a file
//! swapped in after the read is left alone (it will be seen as new). A
//! symbolic link is moved or deleted as the link it is, never followed.

use super::safety::Facts;
use rustix::{
    fd::{BorrowedFd, OwnedFd},
    fs::{AtFlags, Mode, OFlags, RenameFlags, openat, renameat_with, statat, unlinkat},
    io::Errno,
};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// A name that is safe to use in `processed/` and `rejected/`: ASCII
/// `[A-Za-z0-9._-]`, at most 100 bytes, never starting with a dot.
pub fn sanitize(name: &[u8]) -> String {
    let mut out: String = name
        .iter()
        .take(100)
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
                b as char
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.starts_with('.') {
        out.insert(0, '_');
    }
    out
}

/// A folder opened without following a link (made 0700 when missing).
pub fn open_private_dir(path: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    open_dir(path)
}

pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// Whether `name` in `dir` is still the file `expected` (same device and
/// inode, not replaced since).
pub fn still_the_file(dir: BorrowedFd<'_>, name: &CStr, expected: &Facts) -> bool {
    statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|stat| Facts::from(&stat).same_file(expected))
        .unwrap_or(false)
}

/// Delete the file `name`, if it is still the one that was read.
pub fn delete(dir: BorrowedFd<'_>, name: &CStr, expected: &Facts) -> io::Result<()> {
    if !still_the_file(dir, name, expected) {
        return Err(io::Error::other(
            "the name no longer leads to the file that was read; left alone",
        ));
    }
    unlinkat(dir, name, AtFlags::empty()).map_err(io::Error::from)
}

/// Move the file `name` into `target` as `new_name` (never over an existing
/// file), if it is still the one that was read. Across file systems the
/// bytes are copied from a fresh no-follow open and the original removed.
pub fn move_into(
    dir: BorrowedFd<'_>,
    name: &CStr,
    expected: &Facts,
    target: BorrowedFd<'_>,
    new_name: &str,
) -> io::Result<()> {
    if !still_the_file(dir, name, expected) {
        return Err(io::Error::other(
            "the name no longer leads to the file that was read; left alone",
        ));
    }
    let new_c = std::ffi::CString::new(new_name).map_err(io::Error::other)?;
    match renameat_with(dir, name, target, &new_c, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::XDEV) => copy_then_remove(dir, name, expected, target, &new_c),
        Err(error) => Err(error.into()),
    }
}

fn copy_then_remove(
    dir: BorrowedFd<'_>,
    name: &CStr,
    expected: &Facts,
    target: BorrowedFd<'_>,
    new_name: &CStr,
) -> io::Result<()> {
    let source = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let facts = Facts::from(&rustix::fs::fstat(&source)?);
    if !facts.same_file(expected) || facts.kind != super::safety::Kind::Regular {
        return Err(io::Error::other("the file changed before it was moved"));
    }
    let out = openat(
        target,
        new_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut out = File::from(out);
    let mut source = File::from(source);
    io::copy(&mut source, &mut out)?;
    out.sync_all()?;
    unlinkat(dir, name, AtFlags::empty())?;
    Ok(())
}

/// Write `<new_name>.reason` next to a rejected file: one line, the failure
/// code and its words, control characters removed.
pub fn write_reason(target: BorrowedFd<'_>, new_name: &str, code: &str, message: &str) {
    let clean: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(500)
        .collect();
    let Ok(path) = std::ffi::CString::new(format!("{new_name}.reason")) else {
        return;
    };
    let Ok(fd) = openat(
        target,
        &path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) else {
        return;
    };
    let _ = writeln!(File::from(fd), "{code}: {clean}");
}

/// A name for the settled file: the time and the sanitised name, with a
/// counter when that exists.
pub fn settled_name(now_ms: u64, name: &[u8], attempt: u32) -> String {
    let base = sanitize(name);
    if attempt == 0 {
        format!("{now_ms}-{base}")
    } else {
        format!("{now_ms}-{attempt}-{base}")
    }
}

/// How many `keep`ed files a folder remembers.
pub const MAX_REMEMBERED: usize = 20_000;

/// The files of `keep` folders (and of folders whose move failed) that were
/// taken already, by device, inode, size and mtime: `<inbox>/watch-state.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Remembered {
    pub folders: std::collections::BTreeMap<String, Vec<[i128; 4]>>,
}

impl Remembered {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        let temp = path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    }
}

/// The key of a taken file.
pub fn key_of(facts: &Facts) -> [i128; 4] {
    [
        i128::from(facts.dev),
        i128::from(facts.ino),
        i128::from(facts.size),
        facts.mtime_ns,
    ]
}
