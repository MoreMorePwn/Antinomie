// SPDX-License-Identifier: GPL-3.0-only
//! Reading the files a catalog lists out of a download, with every size
//! bounded and every file hashed. Nothing in a download is executed.
use super::*;
use std::io::Read;

/// Entries read from one archive before it is refused.
const MAX_SCANNED_MEMBERS: usize = 200_000;
/// Uncompressed bytes read from one gzip stream before it is refused.
const MAX_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

/// What a download held after verification.
#[derive(Debug, Default)]
pub(super) struct Extracted {
    /// SHA-256 of the whole download.
    pub download_sha256: String,
    /// Kept files with the hash computed from the bytes received.
    pub files: Vec<SourceFile>,
    /// Kept files whose hash differs from the catalog (rolling sources only).
    pub changed: u64,
    /// Kept files the catalog does not list (rolling sources only).
    pub unlisted: u64,
    /// Listed files the download no longer holds (rolling sources only).
    pub missing: u64,
}

/// The byte limit for one download of `source`.
pub(super) fn download_limit(source: &SourceFetch) -> u64 {
    if !source.rolling && !source.sha256.is_empty() {
        source.size
    } else {
        source
            .size
            .saturating_mul(2)
            .saturating_add(1024 * 1024)
            .min(MAX_SOURCE_BYTES)
    }
}

/// Extract the files `source` lists from `download` into `dest`.
///
/// A pinned source must match every hash it lists; a difference refuses the
/// install. A rolling source records differences, because the publisher is
/// expected to change it after the catalog was written.
/// `accept_unlisted` decides which unlisted files under the source's rule
/// paths a rolling source also keeps.
pub(super) fn extract(
    download: &Path,
    source: &SourceFetch,
    dest: &Path,
    accept_unlisted: &dyn Fn(&str) -> bool,
    totals: &mut u64,
) -> Result<Extracted, String> {
    let size = fs::metadata(download)
        .map_err(|error| format!("{}: {error}", source.url))?
        .len();
    if size > download_limit(source) {
        return Err(format!("{} is larger than the catalog allows", source.url));
    }
    let mut result = Extracted {
        download_sha256: crate::storage::sha256_file_hex(download)?,
        ..Extracted::default()
    };
    if !source.sha256.is_empty() && result.download_sha256 != source.sha256 && !source.rolling {
        return Err(format!(
            "{} does not match the catalog checksum; upstream changed or the download was altered, and nothing was installed",
            source.url
        ));
    }
    let listed: BTreeMap<&str, &str> = source
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    let mut keep = |path: String, data: Vec<u8>| -> Result<(), String> {
        if seen.contains(&path) {
            return Err(format!("{path} appears twice in {}", source.url));
        }
        let digest = format!("{:x}", Sha256::digest(&data));
        match listed.get(path.as_str()) {
            Some(expected) if *expected == digest => {}
            Some(expected) => {
                if !source.rolling {
                    return Err(format!(
                        "{path} from {} does not match the catalog (expected {expected}, received {digest}); nothing was installed",
                        source.url
                    ));
                }
                result.changed += 1;
            }
            None => result.unlisted += 1,
        }
        *totals = totals.saturating_add(data.len() as u64);
        if *totals > MAX_EXPANDED_BYTES {
            return Err("the downloaded rules exceed the expanded byte limit".into());
        }
        let target = dest.join(&path);
        if let Some(parent) = target.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        fs::write(&target, &data).map_err(|error| format!("write {path}: {error}"))?;
        seen.insert(path.clone());
        result.files.push(SourceFile {
            path,
            sha256: digest,
        });
        Ok(())
    };
    let wanted = |path: &str| -> bool {
        listed.contains_key(path)
            || (source.rolling
                && source
                    .paths
                    .iter()
                    .any(|prefix| path.starts_with(prefix.trim_end_matches('/')))
                && accept_unlisted(path))
    };
    match source.format.as_str() {
        "file" => {
            let data = read_bounded(&mut fs::File::open(download).map_err(|e| e.to_string())?)?;
            let path = source
                .files
                .first()
                .ok_or("a file download names no file")?;
            keep(path.path.clone(), data)?;
        }
        "zip" => extract_zip(download, source, &wanted, &mut keep)?,
        "tar.gz" => extract_tar(download, source, &wanted, &mut keep)?,
        other => return Err(format!("unknown download format {other}")),
    }
    for file in &source.files {
        if !seen.contains(&file.path) {
            if !source.rolling {
                return Err(format!(
                    "{} no longer holds {}; nothing was installed",
                    source.url, file.path
                ));
            }
            result.missing += 1;
        }
    }
    result.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

/// A normal relative member path with `strip` leading components removed.
fn member_path(raw: &str, strip: u32) -> Option<String> {
    let parts: Vec<&str> = raw.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == ".." || *part == ".") || raw.starts_with('/') {
        return None;
    }
    let kept = parts.get(strip as usize..)?;
    if kept.is_empty() {
        return None;
    }
    let path = kept.join("/");
    checked_member_path(&path).ok()?;
    Some(path)
}

fn read_bounded(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    reader
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_FILE_BYTES {
        return Err("a downloaded file exceeds the per-file byte limit".into());
    }
    Ok(data)
}

fn extract_zip(
    download: &Path,
    source: &SourceFetch,
    wanted: &dyn Fn(&str) -> bool,
    keep: &mut dyn FnMut(String, Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    let file = fs::File::open(download).map_err(|error| error.to_string())?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("{}: {error}", source.url))?;
    if archive.len() > MAX_SCANNED_MEMBERS {
        return Err(format!("{} has too many members", source.url));
    }
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| format!("{}: {error}", source.url))?;
        if !member.is_file() {
            continue;
        }
        if member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            continue;
        }
        let Some(path) = member_path(member.name(), source.strip) else {
            continue;
        };
        if !wanted(&path) {
            continue;
        }
        if member.size() > MAX_FILE_BYTES {
            return Err(format!("{path} exceeds the per-file byte limit"));
        }
        let data = read_bounded(&mut member)?;
        keep(path, data)?;
    }
    Ok(())
}

fn extract_tar(
    download: &Path,
    source: &SourceFetch,
    wanted: &dyn Fn(&str) -> bool,
    keep: &mut dyn FnMut(String, Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    let file = fs::File::open(download).map_err(|error| error.to_string())?;
    let decoder = flate2::read::GzDecoder::new(file).take(MAX_STREAM_BYTES);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    let mut members = 0usize;
    for entry in archive
        .entries()
        .map_err(|error| format!("{}: {error}", source.url))?
    {
        members += 1;
        if members > MAX_SCANNED_MEMBERS {
            return Err(format!("{} has too many members", source.url));
        }
        let mut entry = entry.map_err(|error| format!("{}: {error}", source.url))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let raw = entry
            .path()
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .into_owned();
        let Some(path) = member_path(&raw, source.strip) else {
            continue;
        };
        if !wanted(&path) {
            continue;
        }
        if entry.header().size().map_err(|e| e.to_string())? > MAX_FILE_BYTES {
            return Err(format!("{path} exceeds the per-file byte limit"));
        }
        let data = read_bounded(&mut entry)?;
        keep(path, data)?;
    }
    Ok(())
}
