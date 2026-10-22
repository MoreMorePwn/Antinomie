// SPDX-License-Identifier: GPL-3.0-only
//! Content search: does a regular file contain some bytes? Bounded per file,
//! in total and by time; the first hit of a file is reported with its offset
//! and a snippet of the bytes around it.
use super::protocol::{CONTENT_FILE_LIMIT, CONTENT_TOTAL_LIMIT, SNIPPET_LEN};
use ext4_view::Ext4;
use std::time::Instant;

/// Bytes read from a guest file at a time.
const CHUNK: usize = 64 * 1024;
/// Bytes kept from one chunk to the next, so a hit can span the boundary and
/// a snippet has some bytes before it.
const OVERLAP: usize = 64;

/// The bounds of one search (the protocol's constants; tests use smaller).
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub total: u64,
    pub per_file: u64,
    /// Wall-clock budget; `None` for the protocol's.
    pub seconds: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total: CONTENT_TOTAL_LIMIT,
            per_file: CONTENT_FILE_LIMIT,
            seconds: None,
        }
    }
}

/// What one search has used up.
pub(super) struct Budget {
    deadline: Instant,
    total_left: u64,
    per_file: u64,
    pub files_read: u64,
    pub bytes_read: u64,
    pub partial_files: u64,
    /// The time budget ended the search.
    pub timed_out: bool,
    /// The total byte limit ended the search.
    pub byte_limit: bool,
}

impl Budget {
    pub(super) fn new(deadline: Instant, limits: Limits) -> Self {
        Self {
            deadline,
            total_left: limits.total,
            per_file: limits.per_file,
            files_read: 0,
            bytes_read: 0,
            partial_files: 0,
            timed_out: false,
            byte_limit: false,
        }
    }
}

pub(super) struct Hit {
    pub offset: u64,
    pub snippet: String,
}

/// The position of `needle` in `haystack` (`needle` is lower case already
/// when `any_case`).
pub(super) fn find_bytes(haystack: &[u8], needle: &[u8], any_case: bool) -> Option<usize> {
    let (first, rest) = needle.split_first()?;
    if haystack.len() < needle.len() {
        return None;
    }
    let last_start = haystack.len() - needle.len();
    let mut at = 0;
    while at <= last_start {
        let candidate = haystack[at..=last_start].iter().position(|byte| {
            if any_case {
                byte.to_ascii_lowercase() == *first
            } else {
                byte == first
            }
        })? + at;
        let tail = &haystack[candidate + 1..candidate + needle.len()];
        let same = if any_case {
            tail.eq_ignore_ascii_case(rest)
        } else {
            tail == rest
        };
        if same {
            return Some(candidate);
        }
        at = candidate + 1;
    }
    None
}

/// Printable ASCII as is, every other byte a dot: a snippet of arbitrary
/// bytes never carries control characters or direction overrides.
fn snippet(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if (0x20..0x7f).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

/// Search the file at `path` for `needle`. `None` when it is not there, the
/// file cannot be read, or the budget ran out (the budget says which).
pub(super) fn search_file(
    fs: &Ext4,
    path: &ext4_view::PathBuf,
    needle: &[u8],
    any_case: bool,
    budget: &mut Budget,
) -> Option<Hit> {
    if budget.total_left == 0 {
        budget.byte_limit = true;
        return None;
    }
    if Instant::now() >= budget.deadline {
        budget.timed_out = true;
        return None;
    }
    let mut file = fs.open(path).ok()?;
    let size = fs.symlink_metadata(path).ok()?.len();
    if size == 0 {
        return None;
    }
    budget.files_read += 1;
    let allowed = size.min(budget.per_file);
    if size > budget.per_file {
        budget.partial_files += 1;
    }
    let mut window: Vec<u8> = Vec::with_capacity(CHUNK + OVERLAP);
    let mut window_start = 0u64;
    let mut read = 0u64;
    let mut buffer = vec![0u8; CHUNK];
    while read < allowed {
        if Instant::now() >= budget.deadline {
            budget.timed_out = true;
            return None;
        }
        let want = (allowed - read).min(CHUNK as u64).min(budget.total_left) as usize;
        if want == 0 {
            budget.byte_limit = true;
            return None;
        }
        let count = file.read_bytes(&mut buffer[..want]).ok()?;
        if count == 0 {
            break;
        }
        read += count as u64;
        budget.total_left -= count as u64;
        budget.bytes_read += count as u64;
        window.extend_from_slice(&buffer[..count]);
        if let Some(at) = find_bytes(&window, needle, any_case) {
            let from = at.saturating_sub(SNIPPET_LEN / 3);
            let to = (at + needle.len() + SNIPPET_LEN * 2 / 3).min(window.len());
            return Some(Hit {
                offset: window_start + at as u64,
                snippet: snippet(&window[from..to]),
            });
        }
        // Keep the tail: a hit can start in it and finish in the next chunk.
        let keep = OVERLAP.max(needle.len() - 1).min(window.len());
        let drop = window.len() - keep;
        window.drain(..drop);
        window_start += drop as u64;
    }
    None
}
