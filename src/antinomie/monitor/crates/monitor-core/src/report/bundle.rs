// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The evidence bundle: a `.zip` written next to the report with the run's
//! packet captures, the files the run dropped (an inner AES-256 archive with
//! the password `infected`, the same convention and mode as the sample
//! library's archives), the sample's custody export, and a hash manifest. The
//! outer archive is not encrypted so the manifest and the custody record can
//! be read and checked without the password. Every file's SHA-256 is taken
//! while it is copied and written to `manifest.json` and `manifest.sha256`
//! (`sha256sum -c` format).
use super::{DROPPED_PASSWORD, iso};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipWriter};

/// Bytes of one dropped file, per file and for all of them.
pub const DROPPED_FILE_LIMIT: u64 = 64 * 1024 * 1024;
pub const DROPPED_TOTAL_LIMIT: u64 = 512 * 1024 * 1024;

/// Writes a dropped file's bytes, exactly its `size`.
pub type WriteBytes = Box<dyn FnOnce(&mut dyn Write) -> io::Result<()>>;

/// A dropped file as the inner archive holds it: entry name, guest path,
/// size, SHA-256 of the bytes, the guest's own hash.
type Listed = (String, String, u64, String, String);

/// A file the run dropped, ready to be written once.
pub struct DroppedFile {
    /// Where it was in the guest.
    pub path: String,
    /// SHA-256 of its reconstructed bytes; checked while they are written.
    pub sha256: String,
    /// The hash the guest took, when it took one.
    pub guest_sha256: String,
    pub size: u64,
    /// Writes exactly `size` bytes.
    pub write: WriteBytes,
}

/// What goes into the bundle.
pub struct BundleInput {
    /// Packet captures of the run, oldest first.
    pub captures: Vec<PathBuf>,
    pub dropped: Vec<DroppedFile>,
    /// Files not bundled, and why (the caps, an incomplete reconstruction).
    pub skipped: Vec<(String, String)>,
    /// The sample's custody record, already exported: the JSON and its verifier.
    pub custody: Vec<PathBuf>,
    pub run_id: String,
    pub generated_ms: u64,
}

/// One file of the bundle as the manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// What a bundle holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundled {
    pub path: PathBuf,
    pub files: Vec<ManifestFile>,
    /// Guest path to the entry inside `dropped-files.zip`.
    pub dropped: Vec<(String, String)>,
    pub skipped: Vec<(String, String)>,
}

/// A writer that hashes what passes through it.
struct Hashing<'a, W: Write> {
    inner: &'a mut W,
    hash: Sha256,
    size: u64,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn plain(large: bool) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(1))
        .large_file(large)
        .unix_permissions(0o600)
}

/// Add `reader` as `name`, returning its size and SHA-256.
fn add_stream<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    options: SimpleFileOptions,
    reader: &mut dyn Read,
) -> Result<(u64, String), String> {
    zip.start_file(name, options)
        .map_err(|e| format!("{name}: {e}"))?;
    let mut sink = Hashing {
        inner: zip,
        hash: Sha256::new(),
        size: 0,
    };
    io::copy(reader, &mut sink).map_err(|e| format!("{name}: {e}"))?;
    Ok((sink.size, hex(&sink.hash.finalize())))
}

fn add_bytes<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
) -> Result<ManifestFile, String> {
    let (size, sha256) = add_stream(zip, name, plain(false), &mut &bytes[..])?;
    Ok(ManifestFile {
        path: name.to_owned(),
        size,
        sha256,
    })
}

/// The inner archive of dropped files, written to `temp`. Returns what it
/// holds as `(entry, path, size, sha256)`.
fn write_dropped(temp: &Path, dropped: Vec<DroppedFile>) -> Result<Vec<Listed>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(|e| format!("{}: {e}", temp.display()))?;
    let mut zip = ZipWriter::new(file);
    let encrypted = || {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(1))
            .with_aes_encryption(AesMode::Aes256, DROPPED_PASSWORD)
    };
    let mut listed = Vec::new();
    for item in dropped {
        let entry = format!("{}.bin", item.sha256);
        // Two paths with the same bytes share one entry.
        if listed
            .iter()
            .any(|row: &(String, String, u64, String, String)| row.0 == entry)
        {
            listed.push((entry, item.path, item.size, item.sha256, item.guest_sha256));
            continue;
        }
        zip.start_file(&entry, encrypted())
            .map_err(|e| format!("{entry}: {e}"))?;
        let mut sink = Hashing {
            inner: &mut zip,
            hash: Sha256::new(),
            size: 0,
        };
        (item.write)(&mut sink).map_err(|e| format!("{}: {e}", item.path))?;
        let (size, got) = (sink.size, hex(&sink.hash.finalize()));
        if got != item.sha256 || size != item.size {
            return Err(format!(
                "{}: the bytes written hash to {got}, not the {} the reconstruction gave",
                item.path, item.sha256
            ));
        }
        listed.push((entry, item.path, item.size, item.sha256, item.guest_sha256));
    }
    let index: Vec<_> = listed
        .iter()
        .map(|(entry, path, size, sha256, guest)| {
            json!({"entry": entry, "guest_path": path, "size": size, "sha256": sha256, "guest_sha256": guest})
        })
        .collect();
    let text = serde_json::to_string_pretty(&json!({
        "note": "Files the run dropped, as reconstructed from its recording. Password: infected (AES-256).",
        "files": index,
    }))
    .map_err(|e| e.to_string())?;
    zip.start_file("files.json", encrypted())
        .map_err(|e| e.to_string())?;
    zip.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(listed)
}

/// Write the bundle to `path` (which must not exist). `temp` is a scratch
/// path for the inner archive, removed before returning.
pub fn write(path: &Path, temp: &Path, input: BundleInput) -> Result<Bundled, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let result = write_into(out, temp, input, path);
    let _ = std::fs::remove_file(temp);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn write_into(out: File, temp: &Path, input: BundleInput, path: &Path) -> Result<Bundled, String> {
    let mut zip = ZipWriter::new(out);
    let mut files: Vec<ManifestFile> = Vec::new();
    let mut skipped = input.skipped;
    let mut used = std::collections::BTreeSet::new();
    for capture in &input.captures {
        let name = capture
            .file_name()
            .map_or_else(|| "capture".into(), |n| n.to_string_lossy().into_owned());
        let mut entry = format!("capture/{name}");
        while !used.insert(entry.clone()) {
            entry.push('_');
        }
        match File::open(capture) {
            Ok(mut file) => {
                let large = file
                    .metadata()
                    .map_or(true, |m| m.len() > u64::from(u32::MAX));
                let (size, sha256) = add_stream(&mut zip, &entry, plain(large), &mut file)?;
                files.push(ManifestFile {
                    path: entry,
                    size,
                    sha256,
                });
            }
            Err(error) => skipped.push((capture.display().to_string(), error.to_string())),
        }
    }
    let mut dropped_map = Vec::new();
    if !input.dropped.is_empty() {
        let listed = write_dropped(temp, input.dropped)?;
        let mut inner = File::open(temp).map_err(|e| format!("{}: {e}", temp.display()))?;
        let large = inner
            .metadata()
            .map_or(true, |m| m.len() > u64::from(u32::MAX));
        // Already compressed and encrypted: stored as it is.
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(large)
            .unix_permissions(0o600);
        let (size, sha256) = add_stream(&mut zip, "dropped-files.zip", options, &mut inner)?;
        files.push(ManifestFile {
            path: "dropped-files.zip".into(),
            size,
            sha256,
        });
        for (entry, guest_path, size, sha256, _) in &listed {
            dropped_map.push((guest_path.clone(), format!("dropped-files.zip/{entry}")));
            files.push(ManifestFile {
                path: format!("dropped-files.zip/{entry}"),
                size: *size,
                sha256: sha256.clone(),
            });
        }
    }
    for custody in &input.custody {
        let name = custody
            .file_name()
            .map_or_else(|| "custody".into(), |n| n.to_string_lossy().into_owned());
        let bytes = std::fs::read(custody).map_err(|e| format!("{}: {e}", custody.display()))?;
        files.push(add_bytes(&mut zip, &format!("custody/{name}"), &bytes)?);
    }
    let listing: Vec<_> = files
        .iter()
        .map(|f| json!({"path": f.path, "size": f.size, "sha256": f.sha256}))
        .collect();
    let manifest = serde_json::to_string_pretty(&json!({
        "schema": "antinomie-evidence-bundle",
        "version": 1,
        "generated": iso(input.generated_ms),
        "run": input.run_id,
        "dropped_files_archive": {"password": DROPPED_PASSWORD, "encryption": "AES-256 (WinZip AE-2)"},
        "files": listing,
        "dropped": dropped_map
            .iter()
            .map(|(guest, entry)| json!({"guest_path": guest, "entry": entry}))
            .collect::<Vec<_>>(),
        "skipped": skipped
            .iter()
            .map(|(what, why)| json!({"what": what, "reason": why}))
            .collect::<Vec<_>>(),
    }))
    .map_err(|e| e.to_string())?;
    add_bytes(&mut zip, "manifest.json", manifest.as_bytes())?;
    // Entries of the inner archive are listed in the manifest but are not
    // files of this archive, so the checksum list names only real members.
    let sums: String = files
        .iter()
        .filter(|f| !f.path.starts_with("dropped-files.zip/"))
        .map(|f| format!("{}  {}\n", f.sha256, f.path))
        .collect();
    add_bytes(&mut zip, "manifest.sha256", sums.as_bytes())?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(Bundled {
        path: path.to_path_buf(),
        files,
        dropped: dropped_map,
        skipped,
    })
}

/// Check a bundle: every member listed in `manifest.sha256` hashes to the
/// value there, and `manifest.json` lists the same hashes. Returns the files
/// the manifest lists.
pub fn verify(path: &Path) -> Result<Vec<ManifestFile>, String> {
    let mut archive = zip::ZipArchive::new(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut read = |name: &str| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        archive
            .by_name(name)
            .map_err(|e| format!("{name}: {e}"))?
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{name}: {e}"))?;
        Ok(bytes)
    };
    let sums = String::from_utf8(read("manifest.sha256")?).map_err(|e| e.to_string())?;
    for line in sums.lines() {
        let (hash, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("manifest.sha256: bad line {line:?}"))?;
        let got = crate::storage::sha256_hex(&read(name)?);
        if got != hash {
            return Err(format!(
                "{name}: hash {got} is not the {hash} the manifest lists"
            ));
        }
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&read("manifest.json")?).map_err(|e| e.to_string())?;
    let files: Vec<ManifestFile> =
        serde_json::from_value(manifest["files"].clone()).map_err(|e| e.to_string())?;
    for line in sums.lines() {
        let (hash, name) = line.split_once("  ").unwrap_or_default();
        if !files.iter().any(|f| f.path == name && f.sha256 == hash) {
            return Err(format!(
                "{name}: manifest.json and manifest.sha256 disagree"
            ));
        }
    }
    Ok(files)
}

/// The bytes of dropped file `entry` (as `manifest.json` names it, for
/// example `dropped-files.zip/<sha256>.bin`) read from the bundle with the
/// archive password.
pub fn open_dropped(path: &Path, entry: &str) -> Result<Vec<u8>, String> {
    let name = entry
        .strip_prefix("dropped-files.zip/")
        .ok_or_else(|| format!("{entry} is not an entry of dropped-files.zip"))?;
    let mut outer = zip::ZipArchive::new(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut inner_bytes = Vec::new();
    outer
        .by_name("dropped-files.zip")
        .map_err(|e| e.to_string())?
        .read_to_end(&mut inner_bytes)
        .map_err(|e| e.to_string())?;
    let mut inner =
        zip::ZipArchive::new(io::Cursor::new(inner_bytes)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    inner
        .by_name_decrypt(name, DROPPED_PASSWORD.as_bytes())
        .map_err(|e| format!("{name}: {e}"))?
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(bytes)
}
