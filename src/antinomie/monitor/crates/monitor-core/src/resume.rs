// SPDX-License-Identifier: GPL-3.0-only
//! Downloads that continue where a cancelled or interrupted one stopped, and
//! start again from zero when they cannot.
//!
//! A partial file is only kept in the download's own staging place, next to a
//! small record (`<file>.resume`) of what it is: the item's key (its pinned
//! hash and address) and the validators the server sent (`ETag`,
//! `Last-Modified`). The next attempt resumes (`curl -C -`, with `If-Range`
//! when the server gave a validator) only when the record matches the item and
//! the partial file is not larger than the item. Otherwise, or when the server
//! answers the range request with the whole file (curl exit 33) or with
//! different validators, the partial file is deleted and the download starts
//! again, with a short reason for the person to read. The caller still checks
//! the finished file against its pinned SHA-256 or SHA-512 and starts over
//! once when that fails.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::byte_size::short_size;

/// What is being downloaded, as the record keeps it.
pub struct Item<'a> {
    /// Shown to the person: "Debian 13 base", "Ghidra".
    pub label: &'a str,
    /// Anything that changes when the expected file changes: the pinned hash,
    /// the size, the address. A partial file is only resumed for the same key.
    pub key: &'a str,
    /// The size the finished file must have, when it is known.
    pub size: Option<u64>,
}

/// curl's exit code for "the server does not support or accept byte ranges".
const CURL_RANGE_ERROR: i32 = 33;

#[derive(Serialize, Deserialize, Default, Clone)]
struct Record {
    key: String,
    etag: Option<String>,
    last_modified: Option<String>,
}

fn side(dest: &Path, extension: &str) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(extension);
    dest.with_file_name(name)
}

fn record_path(dest: &Path) -> PathBuf {
    side(dest, ".resume")
}

fn headers_path(dest: &Path) -> PathBuf {
    side(dest, ".headers")
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |meta| meta.len())
}

/// Delete the partial file and everything recorded about it.
pub fn discard(dest: &Path) {
    let _ = fs::remove_file(dest);
    forget(dest);
}

/// Delete only the record and header dump, keeping `dest` (a finished file).
fn forget(dest: &Path) {
    let _ = fs::remove_file(record_path(dest));
    let _ = fs::remove_file(headers_path(dest));
}

/// The partial downloads kept in `dir`: files with a resume record beside them.
pub fn kept_in(dir: &Path) -> u64 {
    fs::read_dir(dir).map_or(0, |entries| {
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && record_path(path).is_file())
            .map(|path| file_len(&path))
            .sum()
    })
}

/// What a cancelled base build tells the person. A build is not resumed (a
/// build step is not a download): the next one starts from the beginning. Only
/// a kernel source or cloud image download under way keeps its partial file.
pub fn cancelled_build_text(data_dir: &Path) -> String {
    let root = data_dir.join("build");
    let kept = kept_in(&root.join("inputs")) + kept_in(&root.join("builder"));
    if kept > 0 {
        format!(
            "Cancelled. A new build starts from the beginning; the {} already downloaded is kept and resumes when it can.",
            short_size(kept)
        )
    } else {
        "Cancelled. Nothing was changed; a new build starts from the beginning.".to_owned()
    }
}

/// The size of the partial file kept for `dest` (0 when none).
pub fn kept_size(dest: &Path) -> u64 {
    if record_path(dest).is_file() {
        file_len(dest)
    } else {
        0
    }
}

fn read_record(dest: &Path) -> Option<Record> {
    serde_json::from_slice(&fs::read(record_path(dest)).ok()?).ok()
}

fn write_record(dest: &Path, record: &Record) {
    if let Ok(bytes) = serde_json::to_vec(record) {
        let _ = fs::write(record_path(dest), bytes);
    }
}

/// `Ok(())` to resume the partial file, `Err(reason)` to start again.
fn check(dest: &Path, item: &Item) -> Result<(), &'static str> {
    let len = file_len(dest);
    let Some(record) = read_record(dest) else {
        return Err("nothing records where the partial file came from");
    };
    if record.key != item.key {
        return Err("the item changed since the partial file was saved");
    }
    if item.size.is_some_and(|size| len > size) {
        return Err("the partial file is larger than the item");
    }
    Ok(())
}

/// The validators of the last successful response in a curl header dump.
fn read_validators(dest: &Path) -> (Option<String>, Option<String>) {
    let text = fs::read_to_string(headers_path(dest)).unwrap_or_default();
    let (mut etag, mut modified, mut ok) = (None, None, false);
    let (mut last_etag, mut last_modified) = (None, None);
    for line in text.lines() {
        let line = line.trim_end();
        if line.starts_with("HTTP/") {
            ok = line
                .split_whitespace()
                .nth(1)
                .is_some_and(|code| code == "200" || code == "206");
            (etag, modified) = (None, None);
        } else if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_owned();
            match name.to_ascii_lowercase().as_str() {
                "etag" => etag = Some(value),
                "last-modified" => modified = Some(value),
                _ => {}
            }
        }
        if ok {
            (last_etag, last_modified) = (etag.clone(), modified.clone());
        }
    }
    (last_etag, last_modified)
}

/// Whether the server sent validators that differ from the recorded ones.
fn drifted(record: &Record, etag: &Option<String>, modified: &Option<String>) -> bool {
    let differs = |was: &Option<String>, now: &Option<String>| matches!((was, now), (Some(was), Some(now)) if was != now);
    differs(&record.etag, etag) || differs(&record.last_modified, modified)
}

/// Download `url` to `dest`, resuming a kept partial file when that is safe.
/// `note` hears one line when the transfer resumes ("Resuming Ghidra from
/// 22.0 MiB") or starts again for a reason; nothing when it starts fresh.
/// A set `cancel` stops it within a moment and keeps the partial file (with
/// its record) for the next attempt: the error is "`what` cancelled".
#[allow(clippy::too_many_arguments)]
pub fn fetch(
    curl: &Path,
    url: &str,
    dest: &Path,
    item: &Item,
    cancel: &AtomicBool,
    what: &str,
    interval: Duration,
    mut tick: impl FnMut(),
    note: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let mut resuming = false;
    if file_len(dest) > 0 {
        match check(dest, item) {
            Ok(()) => {
                resuming = true;
                note(&format!(
                    "Resuming {} from {}",
                    item.label,
                    short_size(file_len(dest))
                ));
            }
            Err(reason) => {
                discard(dest);
                note(&format!("Starting {} again: {reason}", item.label));
            }
        }
    } else {
        discard(dest);
    }
    // The first resumed request is not retried: a server that cannot resume
    // says so at once (curl 33) and the retries would only delay the restart.
    let mut probing = resuming;
    loop {
        if resuming && item.size == Some(file_len(dest)) {
            // Complete already: the caller checks its hash.
            forget(dest);
            return Ok(());
        }
        let mut record = read_record(dest)
            .filter(|_| resuming)
            .unwrap_or_else(|| Record {
                key: item.key.to_owned(),
                ..Record::default()
            });
        write_record(dest, &record);
        let headers = headers_path(dest);
        let _ = fs::remove_file(&headers);
        let mut extra = vec!["-D".to_owned(), headers.to_string_lossy().into_owned()];
        if probing {
            extra.extend(["--retry".to_owned(), "0".to_owned()]);
        }
        if resuming && let Some(validator) = record.etag.as_ref().or(record.last_modified.as_ref())
        {
            extra.push("-H".into());
            extra.push(format!("If-Range: {validator}"));
        }
        let mut child = crate::distribution::spawn_download(curl, url, dest, &extra)?;
        let outcome = crate::cancel::wait_every(&mut child, cancel, interval, &mut tick)?;
        let (etag, modified) = read_validators(dest);
        let moved = resuming && drifted(&record, &etag, &modified);
        record.etag = record.etag.or(etag);
        record.last_modified = record.last_modified.or(modified);
        let _ = fs::remove_file(&headers);
        match outcome {
            None => {
                if file_len(dest) == 0 {
                    discard(dest);
                } else {
                    write_record(dest, &record);
                }
                return Err(format!("{what} cancelled"));
            }
            Some(status) if status.success() && !moved => {
                forget(dest);
                return Ok(());
            }
            Some(status) if resuming && (moved || status.code() == Some(CURL_RANGE_ERROR)) => {
                discard(dest);
                note(&format!(
                    "Starting {} again: the server changed it or cannot resume it",
                    item.label
                ));
                resuming = false;
            }
            Some(_) if probing => {
                // Not a refusal to resume: ask again with the usual retries.
                probing = false;
                write_record(dest, &record);
            }
            Some(status) => {
                // A network failure keeps what arrived, to resume from.
                write_record(dest, &record);
                return crate::distribution::download_result(&mut child, status, url);
            }
        }
    }
}

#[cfg(test)]
mod tests;
