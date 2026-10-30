// SPDX-License-Identifier: GPL-3.0-only
//! Putting bytes into the library: files added from this computer, downloads,
//! programs sent into or run in a VM. Every route ends in [`Library::add_bytes`]:
//! the bytes are hashed on the host, never run or unpacked, and the same
//! bytes arriving again only add an origin.
use super::{
    MAX_SAMPLE, SampleInfo, archive,
    custody::CustodyEvent,
    library::{Library, NewOrigin, OriginKind, Tag, now_ms},
};
use rusqlite::{OptionalExtension, params};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

/// What the analyst states about a sample when adding it.
#[derive(Clone, Debug, Default)]
pub struct NewSample {
    /// Empty takes the origin's name.
    pub name: String,
    pub description: String,
    pub tags: Vec<Tag>,
    pub origin: NewOrigin,
    /// The source's own record, for a download.
    pub info: Option<SampleInfo>,
}

/// The result of adding bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Added {
    pub sha256: String,
    /// The bytes were not in the library before.
    pub new: bool,
}

/// What a file looks like before it is added: read and hashed, never run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileProbe {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// `elf`, `sh`, `py`, `exe`… (see [`detect_type`]).
    pub file_type: String,
    pub arch: String,
    /// Another route already brought these bytes in.
    pub known: bool,
}

/// What the library asks of a file it adds: a regular file within the size
/// limit, read once.
fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > MAX_SAMPLE {
        return Err(format!(
            "{} is larger than the {} MiB a sample may be",
            path.display(),
            MAX_SAMPLE >> 20
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .and_then(|file| file.take(MAX_SAMPLE + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_SAMPLE {
        return Err("the file grew while it was read".into());
    }
    Ok(bytes)
}

/// The kind of a file from its first bytes, in MalwareBazaar's words, and the
/// architecture of an ELF. Magic only: nothing is parsed further.
pub fn detect_type(bytes: &[u8]) -> (&'static str, Option<&'static str>) {
    if let Some(arch) = super::elf_arch(bytes) {
        return ("elf", Some(arch));
    }
    if let Some(rest) = bytes.strip_prefix(b"#!") {
        let line = rest.split(|b| *b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        let mut words = line.split_whitespace();
        let mut interpreter = words.next().unwrap_or_default();
        if interpreter.ends_with("/env") {
            interpreter = words.next().unwrap_or_default();
        }
        let name = interpreter.rsplit('/').next().unwrap_or_default();
        return (
            match name {
                "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" => "sh",
                n if n.starts_with("python") => "py",
                "perl" => "pl",
                _ => "script",
            },
            None,
        );
    }
    match bytes {
        [b'M', b'Z', ..] => ("exe", None),
        [b'P', b'K', 3, 4, ..] => ("zip", None),
        [0x1f, 0x8b, ..] => ("gz", None),
        [b'B', b'Z', b'h', ..] => ("bz2", None),
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => ("xz", None),
        _ => ("data", None),
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// TLSH of a file, empty when it is too small or too uniform for one.
pub(super) fn tlsh_of(bytes: &[u8]) -> String {
    let mut builder = tlsh2::TlshDefaultBuilder::new();
    builder.update(bytes);
    builder
        .build()
        .map(|hash| String::from_utf8_lossy(&hash.hash()).into_owned())
        .unwrap_or_default()
}

fn describe(origin: &NewOrigin) -> String {
    let kind = origin.kind.label();
    let place = [&origin.source, &origin.path]
        .into_iter()
        .find(|text| !text.is_empty());
    match place {
        Some(place) => format!("{kind}: {place}"),
        None => kind.to_owned(),
    }
}

impl Library {
    /// Read and hash a file without keeping anything. For the Add file…
    /// dialog.
    pub fn probe_file(&self, path: &Path) -> Result<FileProbe, String> {
        let bytes = read_file(path)?;
        let (file_type, arch) = detect_type(&bytes);
        let sha256 = hex(Sha256::digest(&bytes));
        Ok(FileProbe {
            name: path
                .file_name()
                .map_or(String::new(), |name| name.to_string_lossy().into_owned()),
            size: bytes.len() as u64,
            known: self.contains(&sha256)?,
            sha256,
            file_type: file_type.into(),
            arch: arch.map(super::arch_label).unwrap_or_default(),
        })
    }

    /// Add the bytes of a file from this computer. With `delete_original`,
    /// the file is deleted only after the archive was read back, matched and
    /// the file still hashes to the same SHA-256; the deletion is an event
    /// with the original path.
    pub fn add_file(
        &mut self,
        path: &Path,
        mut new: NewSample,
        delete_original: bool,
    ) -> Result<Added, String> {
        let bytes = read_file(path)?;
        if new.origin.kind == OriginKind::default() && new.origin.path.is_empty() {
            new.origin.path = path.display().to_string();
        }
        if new.origin.name.is_empty() {
            new.origin.name = path
                .file_name()
                .map_or(String::new(), |name| name.to_string_lossy().into_owned());
        }
        let added = self.add_bytes(&bytes, new)?;
        if delete_original {
            let archive = self.archive_path(&added.sha256)?;
            if !archive::verify(&archive, &added.sha256).is_ok() {
                return Err("the archive did not read back; the original was kept".into());
            }
            if hex(Sha256::digest(read_file(path)?)) != added.sha256 {
                return Err("the file changed after it was added; the original was kept".into());
            }
            fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
            self.note(
                &added.sha256,
                "analyst",
                CustodyEvent::OriginalDeleted {
                    path: path.display().to_string(),
                },
            )?;
        }
        Ok(added)
    }

    /// Add held bytes. A sample already here gains the origin; a sample
    /// whose archive was removed gets its archive back.
    pub fn add_bytes(&mut self, bytes: &[u8], new: NewSample) -> Result<Added, String> {
        if bytes.len() as u64 > MAX_SAMPLE {
            return Err(format!("a sample may be at most {} MiB", MAX_SAMPLE >> 20));
        }
        for tag in &new.tags {
            tag.validate()?;
        }
        let sha256 = hex(Sha256::digest(bytes));
        let existing = self.get(&sha256)?;
        let archive_ok = existing.as_ref().is_some_and(|sample| {
            sample.removed_ms.is_none() && self.archive_path(&sha256).is_ok_and(|p| p.is_file())
        });
        if !archive_ok {
            archive::write_bytes(&self.root, &sha256, bytes)?;
        }
        let (file_type, arch) = detect_type(bytes);
        let info = new.info.clone().unwrap_or_default();
        // A route that gives a path but no name goes by the path's file name.
        let mut new = new;
        if new.origin.name.is_empty() {
            new.origin.name = new
                .origin
                .path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned();
        }
        let name = [&new.name, &new.origin.name, &info.file_name]
            .into_iter()
            .find(|text| !text.is_empty())
            .cloned()
            .unwrap_or_else(|| sha256[..12].to_owned());
        let file_type = if info.file_type.is_empty() {
            file_type.to_owned()
        } else {
            info.file_type.clone()
        };
        let arch = arch
            .map(str::to_owned)
            .or(info.file_arch.clone())
            .unwrap_or_default();
        let at = now_ms() as i64;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if existing.is_none() {
            transaction
                .execute(
                    "INSERT INTO sample(sha256, sha1, md5, tlsh, name, description, size,
                        file_type, arch, family, added_ms, info)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        sha256,
                        hex(Sha1::digest(bytes)),
                        hex(md5::Md5::digest(bytes)),
                        tlsh_of(bytes),
                        name,
                        new.description.trim(),
                        bytes.len() as i64,
                        file_type,
                        arch,
                        info.signature.clone().unwrap_or_default(),
                        at,
                        serde_json::to_string(&info).map_err(|e| e.to_string())?,
                    ],
                )
                .map_err(|e| e.to_string())?;
        } else {
            // A removed sample comes back; a local file that a source now
            // describes gains the source's record.
            transaction
                .execute(
                    "UPDATE sample SET removed_ms=NULL WHERE sha256=?1",
                    [&sha256],
                )
                .map_err(|e| e.to_string())?;
            if new.info.is_some() {
                transaction
                    .execute(
                        "UPDATE sample SET info=?2, family=CASE WHEN family='' THEN ?3 ELSE family END
                         WHERE sha256=?1 AND info='{}'",
                        params![
                            sha256,
                            serde_json::to_string(&info).map_err(|e| e.to_string())?,
                            info.signature.clone().unwrap_or_default()
                        ],
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        transaction
            .execute(
                "INSERT INTO origin(sha256, kind, source, detail, name, path, vm_id, vm_name,
                    run_id, parent, at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    sha256,
                    new.origin.kind.as_str(),
                    new.origin.source,
                    new.origin.detail,
                    new.origin.name,
                    new.origin.path,
                    new.origin.vm_id,
                    new.origin.vm_name,
                    new.origin.run_id,
                    new.origin.parent,
                    at
                ],
            )
            .map_err(|e| e.to_string())?;
        for tag in &new.tags {
            let color = if tag.kind == super::library::TagKind::Custom && tag.color.is_empty() {
                super::library::TAG_COLORS[0]
            } else {
                tag.color.as_str()
            };
            transaction
                .execute(
                    "INSERT OR IGNORE INTO tag(sha256, kind, value, color) VALUES (?1, ?2, ?3, ?4)",
                    params![sha256, tag.kind.as_str(), tag.value.trim(), color],
                )
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        let is_new = existing.is_none() || !archive_ok;
        let origin = describe(&new.origin);
        self.note(
            &sha256,
            "app",
            if is_new {
                CustodyEvent::Added { origin }
            } else {
                CustodyEvent::OriginAdded { origin }
            },
        )?;
        Ok(Added {
            sha256,
            new: is_new,
        })
    }

    /// The bytes of a sample, decrypted in memory and checked against its
    /// SHA-256. A mismatch or a missing archive is an error: a sample that
    /// does not verify is never sent or run.
    pub fn open_bytes(&self, sha256: &str) -> Result<Vec<u8>, String> {
        let record = self
            .get(sha256)?
            .filter(|record| record.removed_ms.is_none())
            .ok_or("this sample is not in the library")?;
        super::open_sample(&self.archive_path(&record.sha256)?, &record.sha256)
    }

    /// Read the archive back and compare; the result is an event.
    pub fn verify(&self, sha256: &str) -> Result<archive::Verification, String> {
        let record = self
            .get(sha256)?
            .ok_or("this sample is not in the library")?;
        if record.removed_ms.is_some() {
            return Ok(archive::Verification::Missing);
        }
        let result = archive::verify(&self.archive_path(&record.sha256)?, &record.sha256);
        self.note(
            &record.sha256,
            "app",
            CustodyEvent::Verified {
                ok: result.is_ok(),
                detail: match &result {
                    archive::Verification::Matches => String::new(),
                    archive::Verification::Missing => "the archive is missing".into(),
                    archive::Verification::Mismatch(error) => error.clone(),
                },
            },
        )?;
        Ok(result)
    }

    /// Verify every sample that has an archive. Archives in the folder
    /// without a record are first brought in as `Found`.
    pub fn verify_all(&mut self) -> Result<Vec<(String, archive::Verification)>, String> {
        self.adopt_unrecorded()?;
        let hashes: Vec<String> = self
            .list()?
            .into_iter()
            .filter(|sample| sample.removed_ms.is_none())
            .map(|sample| sample.sha256)
            .collect();
        let mut results = Vec::new();
        for hash in hashes {
            let result = self.verify(&hash)?;
            results.push((hash, result));
        }
        Ok(results)
    }

    /// Delete the archive; the record, origins, tags and events stay.
    pub fn remove(&mut self, sha256: &str) -> Result<(), String> {
        let sha256 = sha256.to_ascii_lowercase();
        let archive = self.archive_path(&sha256)?;
        match fs::remove_file(&archive) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", archive.display())),
        }
        let changed = self
            .connection
            .execute(
                "UPDATE sample SET removed_ms=?2 WHERE sha256=?1 AND removed_ms IS NULL",
                params![sha256, now_ms() as i64],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0
            && self
                .connection
                .query_row(
                    "SELECT 1 FROM sample WHERE sha256=?1",
                    [&sha256],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .is_none()
        {
            return Err("this sample is not in the library".into());
        }
        self.note(&sha256, "analyst", CustodyEvent::Removed)
    }
}
