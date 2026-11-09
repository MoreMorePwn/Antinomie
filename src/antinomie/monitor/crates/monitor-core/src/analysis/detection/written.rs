// SPDX-License-Identifier: GPL-3.0-only
//! The executables and libraries a run wrote, kept beside the run for the
//! YARA scan. Triage rebuilds each file from the run's recorded writes where
//! it already writes into the run's folder (the digest the window saves, `detect
//! --save`, the Auto lane) and keeps the whole ones here with an index; the scan
//! reads the index and each file by its hash. Nothing here is the run's
//! own file: a file that could not be rebuilt whole is listed with the reason
//! and not scanned.
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The folder under the run's folder.
pub const FOLDER: &str = "written";
/// The index inside [`FOLDER`].
pub const INDEX: &str = "index.json";
/// Files kept for one run.
pub const MAX_FILES: usize = 64;
/// One file's size limit, in octets.
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// All files together, in octets.
pub const MAX_TOTAL_SIZE: u64 = 256 * 1024 * 1024;

/// One kept file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// Where the guest wrote it.
    pub path: String,
    /// The name of the kept file in [`FOLDER`]: its SHA-256.
    pub file: String,
    pub sha256: String,
    pub size: u64,
    /// `executable` or `library`, from the bytes.
    pub kind: String,
}

/// A written executable or library that was not kept, and why.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Skip {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Index {
    pub files: Vec<Entry>,
    pub skipped: Vec<Skip>,
}

/// The run's index; `None` when Triage has not saved one.
pub fn read(run: &Path) -> Option<Index> {
    let directory = run.join(FOLDER);
    let file = crate::archive_io::open_regular(&directory, &directory.join(INDEX)).ok()?;
    use std::io::Read;
    let mut text = Vec::new();
    file.take(8 << 20).read_to_end(&mut text).ok()?;
    serde_json::from_slice(&text).ok()
}

/// Whether bytes start like an ELF file (an executable, a library or an
/// object); the kind is told from its type field.
pub fn elf_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 18 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let little = bytes[5] != 2;
    let kind = if little {
        u16::from_le_bytes([bytes[16], bytes[17]])
    } else {
        u16::from_be_bytes([bytes[16], bytes[17]])
    };
    match kind {
        2 => Some("executable"),
        // A position-independent executable is also type 3; the name tells
        // the two apart no better than the loader does, so both are scanned.
        3 => Some("library"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_headers_tell_executables_from_libraries_and_text_is_neither() {
        let mut elf = vec![0u8; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[5] = 1;
        elf[16] = 2;
        assert_eq!(elf_kind(&elf), Some("executable"));
        elf[16] = 3;
        assert_eq!(elf_kind(&elf), Some("library"));
        elf[16] = 1;
        assert_eq!(elf_kind(&elf), None);
        assert_eq!(elf_kind(b"#!/bin/sh\necho hi\n"), None);
    }
}
