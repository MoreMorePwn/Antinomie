// SPDX-License-Identifier: GPL-3.0-only
//! The one way the app opens a zip it did not write. A zip has two directories
//! (the central one and a local header in front of each entry) and a hostile
//! file can make them disagree, so that two readers see different entries under
//! one name. `open` refuses such an archive, and a name the zip crate cannot
//! decode, so every reader sees the same single definition of an entry.
use std::{
    borrow::Cow,
    io::{Read, Seek},
};
use zip::{ZipArchive, read::ZipFile};

/// Open `reader` as a zip and require the central directory and the local
/// headers to agree: no duplicate names, no entry that overlaps another, and no
/// local header the central directory does not list.
pub(crate) fn open<R: Read + Seek>(reader: R) -> Result<ZipArchive<R>, String> {
    let mut archive = ZipArchive::new(reader).map_err(|error| error.to_string())?;
    if archive.has_duplicate_names() {
        return Err("the zip holds two entries with the same name".into());
    }
    archive
        .validate_header_consistency()
        .map_err(|error| error.to_string())?;
    Ok(archive)
}

/// The decoded name of an entry. The name is only a label: callers still
/// confine it (`enclosed_name`-style checks) before it becomes a path.
pub(crate) fn name<R: Read>(entry: &ZipFile<'_, R>) -> Result<String, String> {
    entry
        .name()
        .map(Cow::into_owned)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    /// A stored zip of `(name, body)` entries, built with the zip crate.
    pub(crate) fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Overwrite the `nth` occurrence (0 = first) of `from` with `to`, which has
    /// the same length. Occurrence 0 is the local header, the last is the
    /// central directory.
    pub(crate) fn patch_name(bytes: &mut [u8], from: &str, to: &str, nth: usize) {
        assert_eq!(from.len(), to.len());
        let at = bytes
            .windows(from.len())
            .enumerate()
            .filter(|(_, window)| *window == from.as_bytes())
            .map(|(at, _)| at)
            .nth(nth)
            .expect("name present");
        bytes[at..at + from.len()].copy_from_slice(to.as_bytes());
    }

    /// A zip whose entries were stored under harmless names, then renamed in both
    /// headers to `names`.
    pub(crate) fn renamed(placeholders: &[&str], names: &[&str]) -> Vec<u8> {
        let entries: Vec<(&str, &[u8])> = placeholders.iter().map(|n| (*n, &b"x"[..])).collect();
        let mut bytes = build(&entries);
        for (placeholder, name) in placeholders.iter().zip(names) {
            patch_name(&mut bytes, placeholder, name, 0);
            patch_name(&mut bytes, placeholder, name, 0);
        }
        bytes
    }

    #[test]
    fn a_plain_archive_opens_and_names_decode() {
        let bytes = build(&[("a.txt", b"one"), ("dir/b.txt", b"two")]);
        let mut archive = open(Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 2);
        assert_eq!(name(&archive.by_index(1).unwrap()).unwrap(), "dir/b.txt");
    }

    #[test]
    fn two_entries_with_one_name_are_refused() {
        let mut bytes = build(&[("a.txt", b"one"), ("b.txt", b"two")]);
        // Rename the second entry in both of its headers.
        patch_name(&mut bytes, "b.txt", "a.txt", 0);
        patch_name(&mut bytes, "b.txt", "a.txt", 0);
        let error = open(Cursor::new(bytes)).err().expect("duplicate refused");
        assert!(!error.is_empty(), "{error}");
    }

    #[test]
    fn a_local_header_that_disagrees_with_the_central_directory_is_refused() {
        // The dual-header trick: the central directory lists "a.txt" while the
        // data in front of it is headed "z.txt".
        let mut bytes = build(&[("a.txt", b"one")]);
        patch_name(&mut bytes, "a.txt", "z.txt", 0);
        assert!(open(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn a_hidden_local_header_the_directory_does_not_list_is_refused() {
        // Two entries are stored but the central directory is cut to list one,
        // so a reader that walks local headers would see a second entry.
        let mut bytes = build(&[("a.txt", b"one"), ("b.txt", b"two")]);
        let eocd = bytes.len() - 22;
        assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06");
        bytes[eocd + 8] = 1; // entries on this disk
        bytes[eocd + 10] = 1; // entries in total
        let first_len = 46 + "a.txt".len() as u32;
        let size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap());
        assert!(size > first_len);
        bytes[eocd + 12..eocd + 16].copy_from_slice(&first_len.to_le_bytes());
        assert!(open(Cursor::new(bytes)).is_err());
    }
}
