// SPDX-License-Identifier: GPL-3.0-only
//! Unwrapping the archive a sample arrives in. MalwareBazaar, vx-underground
//! and most feeds ship a sample as a ZIP encrypted with `infected` (AES or the
//! legacy ZipCrypto). A ZIP with one file in it is opened in memory and its
//! file becomes the sample; the archive itself is only recorded, in the
//! custody log, as where the sample came from. Nothing is written to disk
//! unencrypted and the entry is read only up to the size limit.
use super::{ARCHIVE_PASSWORD, MAX_SAMPLE};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

/// What the custody origin says of an unwrapped archive; the rest is the
/// archive's file name and SHA-256.
pub const DETAIL_PREFIX: &str = "unwrapped from archive ";

/// How a ZIP that arrives is treated.
#[derive(Clone, Default)]
pub struct ArchiveOptions {
    /// The password of an encrypted entry; `infected` when none is given.
    pub password: Option<String>,
    /// The entry to take, when the archive holds several.
    pub entry: Option<String>,
    /// Keep the ZIP as the sample; open nothing.
    pub keep_archive: bool,
    /// The largest entry to read, `MAX_SAMPLE` at most.
    pub limit: Option<u64>,
}

impl std::fmt::Debug for ArchiveOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveOptions")
            .field("password", &self.password.as_ref().map(|_| "..."))
            .field("entry", &self.entry)
            .field("keep_archive", &self.keep_archive)
            .field("limit", &self.limit)
            .finish()
    }
}

/// The sample taken out of an archive.
pub struct Unwrapped {
    pub bytes: Vec<u8>,
    /// The entry's file name (its last path component).
    pub entry: String,
    /// SHA-256 of the archive.
    pub archive_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A name that is safe to show: control characters become spaces.
fn shown(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

fn size_text(size: u64) -> String {
    match size {
        s if s >= 1 << 20 => format!("{:.1} MiB", s as f64 / f64::from(1 << 20)),
        s if s >= 1 << 10 => format!("{:.1} KiB", s as f64 / 1024.0),
        s => format!("{s} bytes"),
    }
}

struct Member {
    index: usize,
    name: String,
    size: u64,
    encrypted: bool,
}

/// The sample inside `bytes` when it is a ZIP that should be opened, `None`
/// when it is kept as it is, or why it cannot be taken.
///
/// - A ZIP with exactly one file is opened (encrypted or not).
/// - A ZIP of several files that is encrypted is refused with the list, unless
///   `entry` names the file to take.
/// - A ZIP of several files that is not encrypted (a jar, an apk, an office
///   file) stays a ZIP, unless `entry` is given.
/// - Anything that is not a readable ZIP stays as it is.
pub fn unwrap_zip(bytes: &[u8], options: &ArchiveOptions) -> Result<Option<Unwrapped>, String> {
    if options.keep_archive || !bytes.starts_with(b"PK\x03\x04") {
        return Ok(None);
    }
    let Ok(mut zip) = crate::zip_safe::open(Cursor::new(bytes)) else {
        return Ok(None);
    };
    let mut members = Vec::new();
    for index in 0..zip.len() {
        let Ok(file) = zip.by_index_raw(index) else {
            return Ok(None);
        };
        if file.is_dir() {
            continue;
        }
        members.push(Member {
            index,
            name: crate::zip_safe::name(&file).unwrap_or_else(|_| "(unreadable name)".into()),
            size: file.size(),
            encrypted: file.encrypted(),
        });
    }
    let encrypted = members.iter().any(|member| member.encrypted);
    let listing = |members: &[Member]| {
        members
            .iter()
            .map(|m| format!("{} ({})", shown(&m.name), size_text(m.size)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let chosen = if let Some(wanted) = &options.entry {
        let Some(found) = members.iter().find(|m| &m.name == wanted) else {
            return Err(format!(
                "the archive has no entry named {}; it holds: {}",
                shown(wanted),
                listing(&members)
            ));
        };
        found
    } else {
        match members.as_slice() {
            [] => return Ok(None),
            [only] => only,
            _ if encrypted => {
                return Err(format!(
                    "the archive holds {} files; pick one with --entry NAME (or --keep-archive to \
                     keep the zip itself): {}",
                    members.len(),
                    listing(&members)
                ));
            }
            _ => return Ok(None),
        }
    };
    let limit = options.limit.unwrap_or(MAX_SAMPLE).min(MAX_SAMPLE);
    if chosen.size > limit {
        return Err(format!(
            "{} is {} inside the archive, above the {} MiB a sample may be",
            shown(&chosen.name),
            size_text(chosen.size),
            limit >> 20
        ));
    }
    let password = options.password.as_deref().unwrap_or(ARCHIVE_PASSWORD);
    let wrong = || {
        if options.password.is_some() {
            "the archive password is wrong".to_owned()
        } else {
            format!(
                "the archive is encrypted with a password other than `{ARCHIVE_PASSWORD}`; give it \
                 with --archive-password"
            )
        }
    };
    let mut buffer = Vec::with_capacity(chosen.size as usize);
    let read = if chosen.encrypted {
        match zip.by_index_decrypt(chosen.index, password.as_bytes()) {
            Ok(mut file) => file.by_ref().take(limit + 1).read_to_end(&mut buffer),
            Err(zip::result::ZipError::InvalidPassword) => return Err(wrong()),
            Err(error) => return Err(format!("the archive cannot be opened: {error}")),
        }
    } else {
        match zip.by_index(chosen.index) {
            Ok(mut file) => file.by_ref().take(limit + 1).read_to_end(&mut buffer),
            Err(error) => return Err(format!("the archive cannot be opened: {error}")),
        }
    };
    if let Err(error) = read {
        // ZipCrypto's password check is one byte, so a wrong password can pass
        // it and show only as a bad checksum or garbled data.
        return Err(if chosen.encrypted {
            wrong()
        } else {
            format!("the archive entry cannot be read: {error}")
        });
    }
    if buffer.len() as u64 > limit {
        return Err(format!(
            "{} grows past the {} MiB a sample may be; the archive was not opened",
            shown(&chosen.name),
            limit >> 20
        ));
    }
    let name = chosen
        .name
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_owned();
    Ok(Some(Unwrapped {
        bytes: buffer,
        entry: shown(&name),
        archive_sha256: hex(&Sha256::digest(bytes)),
    }))
}

/// Record the archive as the origin of the unwrapped sample in `new`: the
/// origin names the entry, and its detail the archive's file name and SHA-256
/// (the custody log shows both).
pub fn mark_origin(new: &mut super::NewSample, archive_name: &str, unwrapped: &Unwrapped) {
    new.origin.name.clone_from(&unwrapped.entry);
    new.origin.detail = format!(
        "{DETAIL_PREFIX}{} (SHA-256 {})",
        shown(archive_name),
        unwrapped.archive_sha256
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn aes(entries: &[(&str, &[u8])], password: &str) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default()
                        .with_aes_encryption(zip::AesMode::Aes256, password),
                )
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn plain(entries: &[(&str, &[u8])]) -> Vec<u8> {
        crate::zip_safe::tests::build(entries)
    }

    /// The legacy ZipCrypto cipher, written out: the zip crate writes it only
    /// behind an unstable flag.
    pub(crate) fn zipcrypto(name: &str, body: &[u8], password: &str) -> Vec<u8> {
        fn crc_table() -> [u32; 256] {
            let mut table = [0u32; 256];
            for (i, slot) in table.iter_mut().enumerate() {
                let mut c = i as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xedb8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
                *slot = c;
            }
            table
        }
        let table = crc_table();
        let update =
            |crc: u32, byte: u8| table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
        let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
        let step = |keys: &mut [u32; 3], byte: u8| {
            keys[0] = update(keys[0], byte);
            keys[1] = keys[1]
                .wrapping_add(keys[0] & 0xff)
                .wrapping_mul(134_775_813)
                .wrapping_add(1);
            keys[2] = update(keys[2], (keys[1] >> 24) as u8);
        };
        for byte in password.bytes() {
            step(&mut keys, byte);
        }
        let mut crc = 0xffff_ffffu32;
        for byte in body {
            crc = update(crc, *byte);
        }
        let crc = !crc;
        let mut header = [7u8; 12];
        header[11] = (crc >> 24) as u8;
        let mut data = Vec::new();
        for byte in header.iter().chain(body) {
            let key = (keys[2] | 2) & 0xffff;
            let stream = ((key * (key ^ 1)) >> 8) as u8;
            data.push(byte ^ stream);
            step(&mut keys, *byte);
        }
        let mut out = Vec::new();
        let local = |out: &mut Vec<u8>, central: bool| {
            out.extend(if central {
                &b"PK\x01\x02"[..]
            } else {
                &b"PK\x03\x04"[..]
            });
            if central {
                out.extend(20u16.to_le_bytes());
            }
            out.extend(20u16.to_le_bytes());
            out.extend(1u16.to_le_bytes()); // encrypted
            out.extend(0u16.to_le_bytes()); // stored
            out.extend(0u16.to_le_bytes());
            out.extend(0x21u16.to_le_bytes());
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((body.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            if central {
                out.extend([0u8; 10]);
                out.extend(0u32.to_le_bytes());
            }
            out.extend(name.as_bytes());
        };
        local(&mut out, false);
        out.extend(&data);
        let central_at = out.len() as u32;
        local(&mut out, true);
        let central_size = out.len() as u32 - central_at;
        out.extend(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
        out.extend(central_size.to_le_bytes());
        out.extend(central_at.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    const BODY: &[u8] = b"#!/bin/sh\necho synthetic sample\n";

    fn take(bytes: &[u8], options: &ArchiveOptions) -> Result<Option<Unwrapped>, String> {
        unwrap_zip(bytes, options)
    }

    #[test]
    fn an_aes_archive_with_the_default_password_is_unwrapped() {
        let zip = aes(&[("sample.sh", BODY)], "infected");
        let got = take(&zip, &ArchiveOptions::default()).unwrap().unwrap();
        assert_eq!(got.bytes, BODY);
        assert_eq!(got.entry, "sample.sh");
        assert_eq!(got.archive_sha256, hex(&Sha256::digest(&zip)));
    }

    #[test]
    fn a_zipcrypto_archive_is_unwrapped() {
        let zip = zipcrypto("dir/a.bin", BODY, "infected");
        let got = take(&zip, &ArchiveOptions::default()).unwrap().unwrap();
        assert_eq!(got.bytes, BODY);
        assert_eq!(got.entry, "a.bin");
        let wrong = take(
            &zip,
            &ArchiveOptions {
                password: Some("nope".into()),
                ..Default::default()
            },
        );
        assert!(wrong.err().is_some_and(|e| e.contains("password")));
    }

    #[test]
    fn a_given_password_is_used_and_a_wrong_one_is_a_clear_error() {
        let zip = aes(&[("a", BODY)], "s3cret");
        let opts = |p: &str| ArchiveOptions {
            password: Some(p.into()),
            ..Default::default()
        };
        assert_eq!(take(&zip, &opts("s3cret")).unwrap().unwrap().bytes, BODY);
        let error = take(&zip, &opts("wrong")).err().unwrap();
        assert!(error.contains("password is wrong"), "{error}");
        let error = take(&zip, &ArchiveOptions::default()).err().unwrap();
        assert!(error.contains("--archive-password"), "{error}");
    }

    #[test]
    fn several_entries_are_refused_with_a_list_unless_one_is_named() {
        let zip = aes(&[("a.bin", b"aaaa"), ("b.bin", b"bbbbbbbb")], "infected");
        let error = take(&zip, &ArchiveOptions::default()).err().unwrap();
        assert!(
            error.contains("a.bin (4 bytes)") && error.contains("b.bin (8 bytes)"),
            "{error}"
        );
        assert!(error.contains("--entry"));
        let pick = ArchiveOptions {
            entry: Some("b.bin".into()),
            ..Default::default()
        };
        assert_eq!(take(&zip, &pick).unwrap().unwrap().bytes, b"bbbbbbbb");
        let missing = ArchiveOptions {
            entry: Some("c.bin".into()),
            ..Default::default()
        };
        let error = take(&zip, &missing).err().unwrap();
        assert!(error.contains("no entry named c.bin") && error.contains("a.bin"));
    }

    #[test]
    fn plain_zips_follow_the_documented_rule() {
        // One file: unwrapped. Several files: a jar-like zip stays a zip.
        let one = plain(&[("x.txt", b"text")]);
        assert_eq!(
            take(&one, &ArchiveOptions::default())
                .unwrap()
                .unwrap()
                .bytes,
            b"text"
        );
        let many = plain(&[("META-INF/MANIFEST.MF", b"m"), ("A.class", b"c")]);
        assert!(take(&many, &ArchiveOptions::default()).unwrap().is_none());
        let pick = ArchiveOptions {
            entry: Some("A.class".into()),
            ..Default::default()
        };
        assert_eq!(take(&many, &pick).unwrap().unwrap().bytes, b"c");
        // --keep-archive keeps even a one-file zip.
        let keep = ArchiveOptions {
            keep_archive: true,
            ..Default::default()
        };
        assert!(take(&one, &keep).unwrap().is_none());
    }

    #[test]
    fn what_is_not_a_zip_stays_as_it_is() {
        let opts = ArchiveOptions::default();
        assert!(take(b"#!/bin/sh\n", &opts).unwrap().is_none());
        assert!(
            take(b"PK\x03\x04 not really a zip", &opts)
                .unwrap()
                .is_none()
        );
        assert!(take(b"", &opts).unwrap().is_none());
    }

    #[test]
    fn an_entry_over_the_limit_is_refused_before_it_is_read() {
        let zip = aes(&[("big.bin", &[7u8; 4096])], "infected");
        let small = ArchiveOptions {
            limit: Some(1024),
            ..Default::default()
        };
        let error = take(&zip, &small).err().unwrap();
        assert!(
            error.contains("big.bin") && error.contains("a sample may be"),
            "{error}"
        );
    }

    #[test]
    fn an_entry_that_lies_about_its_size_is_cut_at_the_limit() {
        // The central directory says 8 bytes; the data is longer.
        let mut zip = plain(&[("lie.bin", &[1u8; 64])]);
        let sizes = 64u32.to_le_bytes();
        let found: Vec<usize> = (0..zip.len() - 4)
            .filter(|&at| zip[at..at + 4] == sizes)
            .collect();
        for at in found {
            zip[at..at + 4].copy_from_slice(&8u32.to_le_bytes());
        }
        let opts = ArchiveOptions {
            limit: Some(8),
            ..Default::default()
        };
        // Either the zip crate refuses the mismatch (kept as a zip) or the
        // read is cut and refused; it is never read past the limit.
        match take(&zip, &opts) {
            Ok(None) | Err(_) => {}
            Ok(Some(got)) => assert!(got.bytes.len() <= 8),
        }
    }

    #[test]
    fn the_origin_records_the_archive() {
        let mut new = super::super::NewSample::default();
        let un = Unwrapped {
            bytes: vec![],
            entry: "a.bin".into(),
            archive_sha256: "ab".repeat(32),
        };
        mark_origin(&mut new, "dump\n.zip", &un);
        assert_eq!(new.origin.name, "a.bin");
        assert!(
            new.origin.detail.starts_with(DETAIL_PREFIX) && new.origin.detail.contains("dump .zip")
        );
        assert!(new.origin.detail.contains(&"ab".repeat(32)));
    }
}
