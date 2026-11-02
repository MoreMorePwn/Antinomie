// SPDX-License-Identifier: GPL-3.0-only
//! Paged reading and on-demand searching of a hostile data file (a RAM dump
//! or the captured memory of one process core) for the Content window. Nothing
//! here loads a file whole: a page is read at an offset, and a search walks the
//! file in blocks, carrying the end of one block into the next so a string or a
//! match across a boundary is found once and whole. Searches are plain byte
//! scans (the Static analysis string extractor and the `regex` crate, whose
//! matching time is linear in the input); they never run what they read.
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Octets read and searched at a time.
pub const BLOCK_SIZE: usize = 1 << 20;
/// Most octets one page read returns.
pub const PAGE_MAX_SIZE: usize = 64 * 1024;
/// How far a regex match may run past the block it starts in.
pub const MATCH_OVERLAP_SIZE: usize = 64 * 1024;
/// Hits a search keeps unless asked for fewer or more.
pub const HITS_DEFAULT_COUNT: usize = 10_000;
/// Most hits any search keeps.
pub const HITS_MAX_COUNT: usize = 200_000;
/// Characters of one hit kept.
pub const HIT_TEXT_MAX_LEN: usize = 512;
/// Shortest and longest minimum string length offered.
pub const MIN_LEN_RANGE: (usize, usize) = (2, 64);
/// Longest regex pattern accepted, in characters.
pub const PATTERN_MAX_LEN: usize = 1024;
/// Compiled size limit of a pattern, in octets.
const REGEX_SIZE_LIMIT: usize = 4 << 20;

/// Readable octets at offsets from zero. A reader that fails reports the error;
/// one that is shorter than it said returns what it has.
pub trait ByteSource: Send + Sync {
    /// Octets the source holds.
    fn size(&self) -> u64;
    /// Read at `offset` into `buffer`; returns the octets read, which is less
    /// than `buffer.len()` only at the end.
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize>;
}

/// A range of a file: a whole dump, or one mapping of a core.
#[derive(Clone, Debug)]
pub struct FileRange {
    pub path: PathBuf,
    /// Offset in the file of the source's first octet.
    pub start: u64,
    pub size: u64,
}

impl FileRange {
    /// The whole file at `path`.
    pub fn whole(path: PathBuf) -> io::Result<Self> {
        let size = std::fs::metadata(&path)?.len();
        Ok(Self {
            path,
            start: 0,
            size,
        })
    }
}

impl ByteSource for FileRange {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let wanted = buffer.len().min((self.size - offset) as usize);
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.start.saturating_add(offset)))?;
        let mut done = 0;
        while done < wanted {
            match file.read(&mut buffer[done..wanted]) {
                Ok(0) => break,
                Ok(count) => done += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(done)
    }
}

/// The page of up to `length` octets at `offset` (at most `PAGE_MAX_SIZE`);
/// empty at and beyond the end.
pub fn read_page(source: &dyn ByteSource, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    let remaining = source.size().saturating_sub(offset);
    let length = length
        .min(PAGE_MAX_SIZE)
        .min(remaining.min(usize::MAX as u64) as usize);
    let mut page = vec![0u8; length];
    let read = source.read_at(offset, &mut page)?;
    page.truncate(read);
    Ok(page)
}

/// Why a search ended before the end of the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    Cancelled,
    /// The hit limit was reached.
    Limit,
    /// The source ended early or could not be read; the rest is not searched.
    Unreadable,
}

/// One string or match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Offset in the source.
    pub offset: u64,
    /// Extent in the source, in octets.
    pub len: u64,
    /// "ASCII", "UTF-16LE" or "match".
    pub kind: &'static str,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// In offset order (strings: ASCII and UTF-16LE interleaved by offset).
    pub hits: Vec<Hit>,
    /// Octets searched.
    pub scanned: u64,
    pub stopped: Option<Stopped>,
}

/// What a strings search looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StringsOptions {
    /// Shortest string, in characters.
    pub min_len: usize,
    pub ascii: bool,
    pub utf16: bool,
    pub max_hits: usize,
}

impl Default for StringsOptions {
    fn default() -> Self {
        Self {
            min_len: 4,
            ascii: true,
            utf16: true,
            max_hits: HITS_DEFAULT_COUNT,
        }
    }
}

fn clip(text: &str) -> String {
    text.chars().take(HIT_TEXT_MAX_LEN).collect()
}

/// Read `length` octets at `position`; a source that ends early is an error.
fn read_block(
    source: &dyn ByteSource,
    position: u64,
    length: usize,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    buffer.resize(length, 0);
    let read = source.read_at(position, buffer)?;
    buffer.truncate(read);
    if read < length {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// Printable strings of `source`. `cancel` is checked once per block and
/// `progress` receives the octets searched so far. Call on a worker thread.
pub fn find_strings(
    source: &dyn ByteSource,
    options: StringsOptions,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Scan {
    let options = StringsOptions {
        min_len: options.min_len.clamp(1, 4096),
        max_hits: options.max_hits.clamp(1, HITS_MAX_COUNT),
        ..options
    };
    let size = source.size();
    let mut scan = Scan::default();
    let mut buffer = Vec::new();
    let mut position = 0u64;
    while position < size {
        if cancel.load(Ordering::Relaxed) {
            scan.stopped = Some(Stopped::Cancelled);
            return scan;
        }
        let length = (size - position).min(BLOCK_SIZE as u64) as usize;
        if read_block(source, position, length, &mut buffer).is_err() {
            scan.stopped = Some(Stopped::Unreadable);
            return scan;
        }
        let last = position + length as u64 == size;
        // A string at the end of a block may go on in the next one: the
        // trailing run of text and zero octets is left for it to read whole.
        let cut = if last {
            length
        } else {
            crate::core_strings::open_tail(&buffer)
        };
        for (offset, found, kind, text) in crate::analysis::find_strings_min(
            &buffer,
            options.min_len,
            options.ascii,
            options.utf16,
        ) {
            if offset >= cut {
                continue;
            }
            if scan.hits.len() >= options.max_hits {
                scan.stopped = Some(Stopped::Limit);
                return scan;
            }
            scan.hits.push(Hit {
                offset: position + offset as u64,
                len: found as u64,
                kind,
                text: clip(&text),
            });
        }
        position += cut as u64;
        scan.scanned = position;
        progress.store(position, Ordering::Relaxed);
    }
    scan
}

/// Compile a pattern for a byte search: no Unicode mode, so `.` and classes
/// match any octet and `\xNN` names one; the compiled size is bounded.
pub fn compile_regex(pattern: &str, case_insensitive: bool) -> Result<regex::bytes::Regex, String> {
    if pattern.is_empty() {
        return Err("Type a pattern first.".into());
    }
    if pattern.chars().count() > PATTERN_MAX_LEN {
        return Err(format!(
            "A pattern is at most {PATTERN_MAX_LEN} characters."
        ));
    }
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|error| error.to_string())
}

/// Matches of `regex` in `source`, none empty. A match is found whole when it
/// is shorter than `MATCH_OVERLAP_SIZE`; a longer one is cut at the end of its
/// window. Same cancel and progress contract as [`find_strings`].
pub fn find_matches(
    source: &dyn ByteSource,
    regex: &regex::bytes::Regex,
    max_hits: usize,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Scan {
    let max_hits = max_hits.clamp(1, HITS_MAX_COUNT);
    let size = source.size();
    let mut scan = Scan::default();
    let mut buffer = Vec::new();
    let mut position = 0u64;
    // Matches may not start before the end of the previous one.
    let mut floor = 0u64;
    while position < size {
        if cancel.load(Ordering::Relaxed) {
            scan.stopped = Some(Stopped::Cancelled);
            return scan;
        }
        let owned = (size - position).min(BLOCK_SIZE as u64) as usize;
        let window = (size - position).min((BLOCK_SIZE + MATCH_OVERLAP_SIZE) as u64) as usize;
        if read_block(source, position, window, &mut buffer).is_err() {
            scan.stopped = Some(Stopped::Unreadable);
            return scan;
        }
        for found in regex.find_iter(&buffer) {
            if found.start() >= owned {
                break;
            }
            let at = position + found.start() as u64;
            if found.is_empty() || at < floor {
                continue;
            }
            if scan.hits.len() >= max_hits {
                scan.stopped = Some(Stopped::Limit);
                return scan;
            }
            floor = position + found.end() as u64;
            scan.hits.push(Hit {
                offset: at,
                len: found.len() as u64,
                kind: "match",
                text: clip(&String::from_utf8_lossy(found.as_bytes())),
            });
        }
        position += owned as u64;
        scan.scanned = position;
        progress.store(position, Ordering::Relaxed);
    }
    scan
}

#[cfg(test)]
mod tests;
