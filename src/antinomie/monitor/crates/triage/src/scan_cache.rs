// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The last index of a whole run, kept in the process for the next export or
//! report of the same recording. A report reads the run with no filter, and
//! so does the index Triage makes when it opens a run: when the recording is
//! as that index saw it (the same files, sizes and modification times, the
//! same request facts: [`current_stamp`]), the report is built from it and
//! the recording is not read again. That second read took an hour on a 3.5 GB
//! recording.
use super::*;
use std::path::PathBuf;
use std::sync::Mutex;

/// How many runs' indexes are kept: the one on screen and the last exported.
/// The tests run in parallel and keep more.
const KEPT: usize = if cfg!(test) { 32 } else { 2 };

/// The indexes kept, newest last, with the folders they indexed.
static LAST: Mutex<Vec<(PathBuf, ArchiveScan)>> = Mutex::new(Vec::new());

fn folder(directory: &Path) -> PathBuf {
    std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf())
}

/// The stamp an index of `directory` made with `request` would carry
/// ([`ScanData::stamp`]): what the files and the request say, and the run's
/// earlier segments.
pub fn current_stamp(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> String {
    let directory = folder(directory);
    let mut stamp = source_stamp(&directory, pcap, pcap_open, request);
    stamp.push_str(&segments::segments_stamp(&segments::run_segments(
        &directory, request,
    )));
    stamp
}

/// Keep `scan`, the index of `directory`, when it read the run whole.
pub fn remember(directory: &Path, scan: &ArchiveScan) {
    // A scan with its rows can answer any filter, sort or page of the run.
    if !scan.whole_run && scan.rows.is_none() {
        return;
    }
    if let Ok(mut last) = LAST.lock() {
        let directory = folder(directory);
        last.retain(|(kept, _)| *kept != directory);
        last.push((directory, scan.clone()));
        let extra = last.len().saturating_sub(KEPT);
        last.drain(..extra);
    }
}

/// The kept index of `directory` when a new one made with `request` would be
/// the same: the recording and the request facts are as it saw them.
pub fn recall(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> Option<ArchiveScan> {
    if !is_whole_run(request) {
        return None;
    }
    let kept = kept_current(directory, pcap, pcap_open, request)?;
    if kept.whole_run {
        return Some(kept);
    }
    // The index on screen is of a filtered view: the whole run is in its rows.
    requery::answer(&kept, request, &Arc::new(AtomicBool::new(false)))?.ok()
}

/// The kept index of `directory` when the recording and the request facts are
/// as it saw them, whatever filter, sort and page it was made with.
fn kept_current(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> Option<ArchiveScan> {
    let directory_key = folder(directory);
    let kept = LAST
        .lock()
        .ok()?
        .iter()
        .find(|(kept, _)| *kept == directory_key)
        .map(|(_, scan)| scan.clone())?;
    (kept.stamp == current_stamp(directory, pcap, pcap_open, request)).then_some(kept)
}

/// The kept index of `directory` made over for `request`, which differs from
/// the one kept only in filters, sorts and pages: no read of the recording.
/// `None` when nothing kept fits, and the caller scans. A timer refresh of a
/// recording that did not change says so, as the scan would.
pub fn derive(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Option<Result<ArchiveScan, String>> {
    let kept = kept_current(directory, pcap, pcap_open, request)?;
    kept.rows.as_ref().filter(|rows| rows.fits(request))?;
    if request.unchanged_since.as_deref() == Some(kept.stamp.as_str()) {
        return Some(Err(UNCHANGED.into()));
    }
    let answer = requery::answer(&kept, request, cancel)?;
    if let (Ok(done), true) = (&answer, request.keep_index) {
        remember(directory, done);
    }
    Some(answer)
}

/// Drop the kept indexes (a caller that wants the memory back).
pub fn forget() {
    if let Ok(mut last) = LAST.lock() {
        last.clear();
    }
}
