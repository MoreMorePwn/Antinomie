// SPDX-License-Identifier: GPL-3.0-only
//! Placing a file the reader extracted: the worker writes `<out>/<request id>`
//! and this module (in the parent, after the worker answered) gives it a
//! sanitized host name. No guest-controlled string becomes a host path before
//! it has been through [`host_leaf`], and the worker's output is only
//! trusted after it was opened without following links.
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Longest host file name part taken from a guest name, in bytes.
const LEAF_LIMIT: usize = 100;

/// A safe host file name from the last component of a guest path: control
/// characters, separators and NUL become `_`, leading dots are dropped (no
/// hidden files, no `.`/`..`) and the length is bounded.
pub fn host_leaf(guest_path: &str) -> String {
    let leaf = guest_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("");
    let mut clean: String = leaf
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '/' | '\\'
                        | ':'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    clean = clean.trim_start_matches('.').trim().to_string();
    let mut end = clean.len().min(LEAF_LIMIT);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean.truncate(end);
    if clean.is_empty() {
        clean = "file".into();
    }
    clean
}

/// Move the worker's `<extract_dir>/<request id>` to
/// `<extract_dir>/<n>-<leaf>` and return the new path. The source must be a
/// regular file created by the worker (not a link); the result is made
/// private (0600), never executable, and must stay inside `extract_dir`.
pub fn place(extract_dir: &Path, request_id: u64, guest_path: &str) -> Result<PathBuf, String> {
    let root = fs::canonicalize(extract_dir)
        .map_err(|error| format!("{}: {error}", extract_dir.display()))?;
    let source = root.join(request_id.to_string());
    let leaf = host_leaf(guest_path);
    // The worker is sandboxed but untrusted: look at the source without
    // following a link it may have planted there.
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| format!("extracted file missing: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("the reader produced something other than a regular file".into());
    }
    let mut index = 1u32;
    let destination = loop {
        let candidate = root.join(format!("{index}-{leaf}"));
        if fs::symlink_metadata(&candidate).is_err() {
            break candidate;
        }
        index = index.checked_add(1).ok_or("too many extracted files")?;
    };
    if destination.parent() != Some(root.as_path()) {
        return Err("extraction path escapes its folder".into());
    }
    fs::rename(&source, &destination).map_err(|error| format!("placing the file: {error}"))?;
    seal(&destination)?;
    Ok(destination)
}

/// Open `path` without following a final link, check that it is a regular
/// file and make it 0600.
fn seal(path: &Path) -> Result<(), String> {
    let fd = rustix::fs::openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| error.to_string())?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err("the extracted file is not a regular file".into());
    }
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_names_become_safe_host_leaves() {
        assert_eq!(host_leaf("/etc/passwd"), "passwd");
        assert_eq!(host_leaf("/etc/.."), "file");
        assert_eq!(host_leaf("/"), "file");
        assert_eq!(host_leaf("/root/.bashrc"), "bashrc");
        assert_eq!(host_leaf("/tmp/a\nb\0c:d\\e"), "a_b_c_d_e");
        assert_eq!(host_leaf("/x/\u{202e}evil\u{200b}"), "_evil_");
        assert!(host_leaf(&format!("/{}", "é".repeat(500))).len() <= LEAF_LIMIT);
        for name in ["..", ".", "...", "", "/", "//"] {
            let leaf = host_leaf(name);
            assert!(!leaf.contains('/') && leaf != "." && leaf != "..");
        }
    }
}
