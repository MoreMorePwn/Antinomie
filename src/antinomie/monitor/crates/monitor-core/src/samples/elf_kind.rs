// SPDX-License-Identifier: GPL-3.0-only
//! Telling an ELF shared library from a program. Both are `ET_DYN`, so the
//! type field is not enough; the header, the program headers and the dynamic
//! section are read (bounded, never run) for the rules in [`is_shared_library`].
use super::MAX_SAMPLE;

const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_SONAME: u64 = 14;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// `DF_1_PIE`: the linker marks a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;
/// Program headers and dynamic entries looked at, at most.
const LIMIT: usize = 4096;

struct Reader<'a> {
    bytes: &'a [u8],
    wide: bool,
    little: bool,
}

impl Reader<'_> {
    fn uint(&self, at: usize, width: usize) -> Option<u64> {
        let raw = self.bytes.get(at..at.checked_add(width)?)?;
        let mut value = 0u64;
        for (i, byte) in raw.iter().enumerate() {
            let shift = 8 * if self.little { i } else { width - 1 - i };
            value |= u64::from(*byte) << shift;
        }
        Some(value)
    }

    /// A word of the file's class (4 bytes in ELF32, 8 in ELF64).
    fn word(&self, at: usize) -> Option<u64> {
        self.uint(at, if self.wide { 8 } else { 4 })
    }
}

/// Whether `bytes` is an ELF shared library rather than a program.
///
/// - Not `ET_DYN`: a program (or an object file).
/// - No `PT_DYNAMIC`: nothing to load as a library; a program.
/// - `DT_FLAGS_1` has `DF_1_PIE`: a position-independent program (a static PIE
///   too, which has no interpreter).
/// - No `PT_INTERP`: a shared library.
/// - A `PT_INTERP` and a `DT_SONAME`: a library that can also be started, like
///   glibc's `libc.so.6`. A PIE program has an interpreter and no soname.
pub fn is_shared_library(bytes: &[u8]) -> bool {
    library_of(bytes).unwrap_or(false)
}

fn library_of(bytes: &[u8]) -> Option<bool> {
    if bytes.len() < 52 || bytes.get(..4)? != b"\x7fELF" {
        return None;
    }
    let wide = match bytes[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match bytes[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let reader = Reader {
        bytes,
        wide,
        little,
    };
    if reader.uint(16, 2)? != u64::from(ET_DYN) {
        return Some(false);
    }
    let (phoff, phentsize, phnum) = if wide {
        (
            reader.uint(32, 8)?,
            reader.uint(54, 2)?,
            reader.uint(56, 2)?,
        )
    } else {
        (
            reader.uint(28, 4)?,
            reader.uint(42, 2)?,
            reader.uint(44, 2)?,
        )
    };
    let minimum = if wide { 56 } else { 32 };
    if phentsize < minimum || phoff > MAX_SAMPLE {
        return Some(false);
    }
    let mut interp = false;
    let mut dynamic = None;
    for index in 0..(phnum as usize).min(LIMIT) {
        let at = usize::try_from(phoff).ok()? + index * phentsize as usize;
        let kind = reader.uint(at, 4)? as u32;
        let (offset, size) = if wide {
            (reader.uint(at + 8, 8)?, reader.uint(at + 32, 8)?)
        } else {
            (reader.uint(at + 4, 4)?, reader.uint(at + 16, 4)?)
        };
        match kind {
            PT_INTERP => interp = true,
            PT_DYNAMIC if dynamic.is_none() => dynamic = Some((offset, size)),
            _ => {}
        }
    }
    let Some((offset, size)) = dynamic else {
        return Some(false);
    };
    let width = if wide { 8 } else { 4 };
    let mut soname = false;
    for index in 0..LIMIT {
        let at = usize::try_from(offset).ok()? + index * 2 * width;
        if at as u64 + 2 * width as u64 > offset.saturating_add(size) {
            break;
        }
        let (Some(tag), Some(value)) = (reader.word(at), reader.word(at + width)) else {
            break;
        };
        match tag {
            DT_NULL => break,
            DT_SONAME => soname = true,
            DT_FLAGS_1 if value & DF_1_PIE != 0 => return Some(false),
            _ => {}
        }
    }
    Some(!interp || soname)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A little-endian ELF64 or ELF32 with the program headers and dynamic
    /// entries given: `(type, entries)` with the dynamic entries as `(tag,
    /// value)`.
    pub(crate) fn elf(
        wide: bool,
        kind: u16,
        interp: bool,
        dynamic: Option<&[(u64, u64)]>,
    ) -> Vec<u8> {
        let (ehsize, phsize) = if wide { (64, 56) } else { (52, 32) };
        let mut headers = Vec::new();
        if interp {
            headers.push((PT_INTERP, 0u64, 0u64));
        }
        let table = ehsize + headers.len() * phsize + usize::from(dynamic.is_some()) * phsize;
        let mut body = Vec::new();
        if let Some(entries) = dynamic {
            for (tag, value) in entries.iter().chain(&[(DT_NULL, 0)]) {
                if wide {
                    body.extend(tag.to_le_bytes());
                    body.extend(value.to_le_bytes());
                } else {
                    body.extend((*tag as u32).to_le_bytes());
                    body.extend((*value as u32).to_le_bytes());
                }
            }
            headers.push((PT_DYNAMIC, table as u64, body.len() as u64));
        }
        let mut bytes = vec![0u8; ehsize];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if wide { 2 } else { 1 };
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&kind.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        if wide {
            bytes[32..40].copy_from_slice(&(ehsize as u64).to_le_bytes());
            bytes[54..56].copy_from_slice(&(phsize as u16).to_le_bytes());
            bytes[56..58].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        } else {
            bytes[28..32].copy_from_slice(&(ehsize as u32).to_le_bytes());
            bytes[42..44].copy_from_slice(&(phsize as u16).to_le_bytes());
            bytes[44..46].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        }
        for (header, offset, size) in headers {
            let mut entry = vec![0u8; phsize];
            entry[..4].copy_from_slice(&header.to_le_bytes());
            if wide {
                entry[8..16].copy_from_slice(&offset.to_le_bytes());
                entry[32..40].copy_from_slice(&size.to_le_bytes());
            } else {
                entry[4..8].copy_from_slice(&(offset as u32).to_le_bytes());
                entry[16..20].copy_from_slice(&(size as u32).to_le_bytes());
            }
            bytes.extend(entry);
        }
        bytes.extend(body);
        bytes
    }

    #[test]
    fn a_shared_object_without_an_interpreter_is_a_library() {
        for wide in [true, false] {
            assert!(
                is_shared_library(&elf(wide, 3, false, Some(&[]))),
                "wide {wide}"
            );
            assert!(is_shared_library(&elf(
                wide,
                3,
                false,
                Some(&[(DT_SONAME, 1)])
            )));
        }
    }

    #[test]
    fn programs_are_not_libraries() {
        for wide in [true, false] {
            // A fixed program, even with a dynamic section.
            assert!(!is_shared_library(&elf(wide, 2, true, Some(&[]))));
            // A PIE: an interpreter, no soname.
            assert!(!is_shared_library(&elf(wide, 3, true, Some(&[(1, 1)]))));
            // A PIE the linker marked, even with a soname.
            assert!(!is_shared_library(&elf(
                wide,
                3,
                true,
                Some(&[(DT_SONAME, 1), (DT_FLAGS_1, DF_1_PIE)])
            )));
            // A static PIE: no interpreter, marked.
            assert!(!is_shared_library(&elf(
                wide,
                3,
                false,
                Some(&[(DT_FLAGS_1, DF_1_PIE | 1)])
            )));
            // No dynamic section at all.
            assert!(!is_shared_library(&elf(wide, 3, false, None)));
        }
    }

    #[test]
    fn a_library_that_can_be_started_is_still_a_library() {
        // glibc's libc.so.6: an interpreter, an entry point, a soname, no PIE flag.
        for wide in [true, false] {
            assert!(is_shared_library(&elf(
                wide,
                3,
                true,
                Some(&[(DT_SONAME, 1), (1, 2)])
            )));
        }
    }

    #[test]
    fn damaged_or_short_files_are_not_libraries() {
        assert!(!is_shared_library(b""));
        assert!(!is_shared_library(b"\x7fELF\x02\x01\x01"));
        let mut cut = elf(true, 3, false, Some(&[]));
        cut.truncate(70);
        assert!(!is_shared_library(&cut));
        let mut bad_class = elf(true, 3, false, Some(&[]));
        bad_class[4] = 9;
        assert!(!is_shared_library(&bad_class));
        // A header table pointing far outside the file.
        let mut far = elf(true, 3, false, Some(&[]));
        far[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(!is_shared_library(&far));
    }
}
