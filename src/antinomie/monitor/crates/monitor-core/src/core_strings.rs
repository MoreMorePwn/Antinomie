// SPDX-License-Identifier: GPL-3.0-only
//! Printable strings of a process core's memory. The Static analysis
//! extractor (`analysis::find_strings`: ASCII of four or more octets, UTF-16LE
//! of four or more characters) runs over each captured mapping in bounded
//! blocks, so no core is ever loaded whole.
use crate::core_dump::CoreDump;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Octets read and searched at a time.
const BLOCK: usize = 1 << 20;
/// Longest string carried into the next block.
const TAIL_MAX: usize = 8192;
/// Strings kept; a core with more is cut short and says so.
pub const MAX_STRINGS: usize = 200_000;
/// Characters of one string kept.
pub const TEXT_MAX: usize = 512;

/// One string found in a mapping of the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreString {
    /// Virtual address in the process.
    pub address: u64,
    /// Offset in the core file.
    pub file_offset: u64,
    /// "ASCII" or "UTF-16LE".
    pub encoding: &'static str,
    /// Extent in the core, in octets.
    pub byte_len: u64,
    /// Index into `CoreDump::mappings`.
    pub mapping: usize,
    pub text: String,
}

/// Why a search ended before the end of the core's memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    Cancelled,
    /// `MAX_STRINGS` were found.
    Limit,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreStrings {
    /// In address order of the core's mappings.
    pub strings: Vec<CoreString>,
    /// Captured octets searched.
    pub scanned: u64,
    pub stopped: Option<Stopped>,
}

/// The captured octets of `core`'s mappings, which is what a search covers.
pub fn captured_size(core: &CoreDump) -> u64 {
    let file = std::fs::metadata(&core.source).map_or(0, |meta| meta.len());
    core.mappings
        .iter()
        .map(|mapping| captured(mapping, file))
        .sum()
}

fn captured(mapping: &crate::core_dump::CoreMapping, file_size: u64) -> u64 {
    mapping
        .available_size
        .min(mapping.memory_size)
        .min(file_size.saturating_sub(mapping.file_offset))
}

/// Where the run of octets that could still be part of a string ends the
/// block: after the last other octet, looking back at most `TAIL_MAX`.
fn open_tail(block: &[u8]) -> usize {
    let floor = block.len().saturating_sub(TAIL_MAX).max(1);
    let mut cut = block.len();
    while cut > floor
        && (block[cut - 1] == 0 || block[cut - 1].is_ascii_graphic() || block[cut - 1] == b' ')
    {
        cut -= 1;
    }
    cut
}

/// Find the printable strings in the captured memory of `core`.
///
/// | Argument | Meaning |
/// |---|---|
/// | `core` | An opened core; its file is read in blocks. |
/// | `cancel` | Checked once per block; a set flag ends the search. |
/// | `progress` | Receives the captured octets searched so far. |
///
/// Call on a background thread: a large core takes a while.
pub fn find(
    core: &CoreDump,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> std::io::Result<CoreStrings> {
    let mut file = File::open(&core.source)?;
    let file_size = file.metadata()?.len();
    let mut result = CoreStrings::default();
    let mut buffer = Vec::new();
    for (index, mapping) in core.mappings.iter().enumerate() {
        let available = captured(mapping, file_size);
        let mut position = 0u64;
        while position < available {
            if cancel.load(Ordering::Relaxed) {
                result.stopped = Some(Stopped::Cancelled);
                return Ok(result);
            }
            let length = (available - position).min(BLOCK as u64) as usize;
            buffer.resize(length, 0);
            file.seek(SeekFrom::Start(mapping.file_offset + position))?;
            if file.read_exact(&mut buffer).is_err() {
                // The core ended early; the rest of this mapping is not there.
                break;
            }
            let last = position + length as u64 == available;
            // A string at the end of a block may go on in the next one: the
            // trailing run of text and zero octets is left for it to read whole.
            let cut = if last { length } else { open_tail(&buffer) };
            let next = position + cut as u64;
            for (offset, found, encoding, text) in crate::analysis::find_strings(&buffer) {
                if offset >= cut {
                    continue;
                }
                if result.strings.len() >= MAX_STRINGS {
                    result.stopped = Some(Stopped::Limit);
                    return Ok(result);
                }
                let at = position + offset as u64;
                result.strings.push(CoreString {
                    address: mapping.start + at,
                    file_offset: mapping.file_offset + at,
                    encoding,
                    byte_len: found as u64,
                    mapping: index,
                    text: text.chars().take(TEXT_MAX).collect(),
                });
            }
            result.scanned += next - position;
            progress.store(result.scanned, Ordering::Relaxed);
            position = next;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_dump::CoreMapping;

    /// A core whose memory is `memory`, split into the given `(start, length)`
    /// mappings laid out one after another in the file after a 64-octet header.
    fn core(name: &str, memory: &[u8], mappings: &[(u64, usize)]) -> CoreDump {
        let path = std::env::temp_dir().join(format!(
            "ant-core-strings-{name}-{}",
            crate::storage::unique_id()
        ));
        let mut file = vec![0u8; 64];
        file.extend_from_slice(memory);
        std::fs::write(&path, &file).unwrap();
        let mut offset = 64u64;
        let mappings = mappings
            .iter()
            .map(|(start, length)| {
                let mapping = CoreMapping {
                    start: *start,
                    memory_size: *length as u64,
                    file_offset: offset,
                    captured_size: *length as u64,
                    available_size: *length as u64,
                    flags: 6,
                };
                offset += *length as u64;
                mapping
            })
            .collect();
        CoreDump {
            source: path,
            source_size: file.len() as u64,
            threads: Vec::new(),
            mappings,
            files: Vec::new(),
            auxv: Vec::new(),
            notes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn run(core: &CoreDump) -> CoreStrings {
        let result = find(core, &AtomicBool::new(false), &AtomicU64::new(0)).unwrap();
        std::fs::remove_file(&core.source).unwrap();
        result
    }

    #[test]
    fn ascii_and_utf16_strings_get_their_virtual_address_and_file_offset() {
        let mut memory = vec![0u8; 32];
        memory[4..9].copy_from_slice(b"hello");
        for (slot, unit) in "wide!".encode_utf16().enumerate() {
            memory[16 + slot * 2] = unit as u8;
            memory[17 + slot * 2] = (unit >> 8) as u8;
        }
        memory[30] = b'a';
        let found = run(&core("kinds", &memory, &[(0x7000, 32)]));
        let summary: Vec<_> = found
            .strings
            .iter()
            .map(|s| (s.address, s.file_offset, s.encoding, s.text.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                (0x7004, 68, "ASCII", "hello"),
                (0x7010, 80, "UTF-16LE", "wide!")
            ]
        );
        assert_eq!(found.strings[1].byte_len, 10);
        assert_eq!(found.scanned, 32);
        assert_eq!(found.stopped, None);
    }

    #[test]
    fn each_string_names_the_mapping_it_is_in() {
        let mut memory = vec![0u8; 16];
        memory[..4].copy_from_slice(b"one!");
        memory[8..12].copy_from_slice(b"two?");
        let found = run(&core("maps", &memory, &[(0x1000, 8), (0x9000, 8)]));
        assert_eq!(found.strings.len(), 2);
        assert_eq!(
            (found.strings[0].mapping, found.strings[0].address),
            (0, 0x1000)
        );
        assert_eq!(
            (found.strings[1].mapping, found.strings[1].address),
            (1, 0x9000)
        );
    }

    #[test]
    fn a_string_across_a_block_boundary_is_found_once_whole() {
        let mut memory = vec![0u8; BLOCK * 2 + 100];
        let at = BLOCK - 3;
        memory[at..at + 10].copy_from_slice(b"spansblock");
        let end = memory.len() - 4;
        memory[end..].copy_from_slice(b"tail");
        let length = memory.len();
        let found = run(&core("blocks", &memory, &[(0x40_0000, length)]));
        let texts: Vec<_> = found.strings.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, ["spansblock", "tail"]);
        assert_eq!(found.strings[0].address, 0x40_0000 + at as u64);
        assert_eq!(found.scanned, length as u64);
    }

    #[test]
    fn an_uncaptured_mapping_is_skipped_and_a_cancelled_search_stops() {
        let memory = b"printable text".to_vec();
        let mut dump = core("gap", &memory, &[(0x1000, 14)]);
        dump.mappings[0].available_size = 0;
        assert!(run(&dump).strings.is_empty());
        let dump = core("cancel", &memory, &[(0x1000, 14)]);
        let found = find(&dump, &AtomicBool::new(true), &AtomicU64::new(0)).unwrap();
        assert_eq!(found.stopped, Some(Stopped::Cancelled));
        assert!(found.strings.is_empty());
        std::fs::remove_file(&dump.source).unwrap();
    }
}
