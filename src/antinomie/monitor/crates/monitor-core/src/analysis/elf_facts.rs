// SPDX-License-Identifier: GPL-3.0-only
//! What an ELF's own headers say, read without trusting the section table:
//! the loader's view (program headers, entry point) is what the kernel and
//! `file` use, and a packed, stripped or cut-off file often has no usable
//! section table at all. Used to name the real reason an analysis tool gave
//! up, to tell static from dynamic, and to flag a truncated file.

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
/// Longest program interpreter path read.
const INTERP_MAX: usize = 256;
const ET_DYN: u16 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_SONAME: u64 = 14;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// `DF_1_PIE`: the linker marked the file a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;
/// Dynamic entries and string lengths read, so a hostile table cannot stall.
const DYNAMIC_MAX: usize = 4096;
const NAME_MAX: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub kind: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Elf {
    pub is_64: bool,
    pub kind: u16,
    pub entry: u64,
    pub segments: Vec<Segment>,
    /// Whether the program header table itself lies inside the file.
    pub table_complete: bool,
    pub section_table: Option<(u64, u64)>,
    pub len: u64,
}

/// How an ELF is linked, from its program headers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Linking {
    Interpreter(String),
    /// A dynamic segment but no interpreter: static-PIE, or a loader itself.
    DynamicWithoutInterpreter,
    Static,
}

struct Reader<'a> {
    bytes: &'a [u8],
    little: bool,
}
impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let b: [u8; 2] = self.bytes.get(at..at + 2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn u64(&self, at: usize) -> Option<u64> {
        let b: [u8; 8] = self.bytes.get(at..at + 8)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Option<Elf> {
    if bytes.get(..4)? != b"\x7fELF" {
        return None;
    }
    let is_64 = match *bytes.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match *bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let r = Reader { bytes, little };
    let len = bytes.len() as u64;
    let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum) = if is_64 {
        (
            r.u64(0x18)?,
            r.u64(0x20)?,
            r.u64(0x28)?,
            r.u16(0x36)?,
            r.u16(0x38)?,
            r.u16(0x3a)?,
            r.u16(0x3c)?,
        )
    } else {
        (
            u64::from(r.u32(0x18)?),
            u64::from(r.u32(0x1c)?),
            u64::from(r.u32(0x20)?),
            r.u16(0x2a)?,
            r.u16(0x2c)?,
            r.u16(0x2e)?,
            r.u16(0x30)?,
        )
    };
    let minimum = if is_64 { 56 } else { 32 };
    let mut segments = Vec::new();
    let mut table_complete = true;
    if phnum > 0 && usize::from(phentsize) >= minimum {
        let table_end = phoff.saturating_add(u64::from(phnum) * u64::from(phentsize));
        table_complete = table_end <= len;
        for index in 0..usize::from(phnum) {
            let at = usize::try_from(phoff)
                .ok()
                .and_then(|o| o.checked_add(index * usize::from(phentsize)));
            let Some(at) = at else { break };
            let segment = if is_64 {
                (|| {
                    Some(Segment {
                        kind: r.u32(at)?,
                        offset: r.u64(at + 8)?,
                        vaddr: r.u64(at + 16)?,
                        filesz: r.u64(at + 32)?,
                    })
                })()
            } else {
                (|| {
                    Some(Segment {
                        kind: r.u32(at)?,
                        offset: u64::from(r.u32(at + 4)?),
                        vaddr: u64::from(r.u32(at + 8)?),
                        filesz: u64::from(r.u32(at + 16)?),
                    })
                })()
            };
            match segment {
                Some(segment) => segments.push(segment),
                None => break,
            }
        }
    }
    Some(Elf {
        is_64,
        kind: r.u16(0x10)?,
        entry,
        segments,
        table_complete,
        section_table: (shoff != 0 && shnum != 0).then(|| {
            (
                shoff,
                shoff.saturating_add(u64::from(shnum) * u64::from(shentsize)),
            )
        }),
        len,
    })
}

/// What the dynamic section names: the libraries the loader must find, the
/// file's own library name, and whether it was linked as a program.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Dynamic {
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub pie: bool,
}

/// A size as the notes say it: "30.3 MB" (decimal, one place).
fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

impl Elf {
    /// Where the loader would find virtual address `vaddr` in the file.
    fn file_offset_of(&self, vaddr: u64) -> Option<u64> {
        self.segments
            .iter()
            .filter(|s| s.kind == PT_LOAD && s.filesz > 0)
            .find(|s| vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz)
            .map(|s| s.offset + (vaddr - s.vaddr))
    }

    /// The dynamic section: needed libraries, SONAME and the PIE flag.
    pub(crate) fn dynamic(&self, bytes: &[u8]) -> Dynamic {
        let mut found = Dynamic::default();
        let Some(segment) = self.segments.iter().find(|s| s.kind == PT_DYNAMIC) else {
            return found;
        };
        let little = bytes.get(5) != Some(&2);
        let r = Reader { bytes, little };
        let width = if self.is_64 { 16 } else { 8 };
        let start = usize::try_from(segment.offset).unwrap_or(usize::MAX);
        let count = usize::try_from(segment.filesz / width as u64)
            .unwrap_or(0)
            .min(DYNAMIC_MAX);
        let (mut needed, mut soname, mut strtab) = (Vec::new(), None, None);
        for index in 0..count {
            let at = start.saturating_add(index * width);
            let (tag, value) = if self.is_64 {
                match (r.u64(at), r.u64(at + 8)) {
                    (Some(tag), Some(value)) => (tag, value),
                    _ => break,
                }
            } else {
                match (r.u32(at), r.u32(at + 4)) {
                    (Some(tag), Some(value)) => (u64::from(tag), u64::from(value)),
                    _ => break,
                }
            };
            match tag {
                DT_NULL => break,
                DT_NEEDED => needed.push(value),
                DT_SONAME => soname = Some(value),
                DT_STRTAB => strtab = Some(value),
                DT_FLAGS_1 => found.pie = value & DF_1_PIE != 0,
                _ => {}
            }
        }
        let Some(table) = strtab.and_then(|vaddr| self.file_offset_of(vaddr)) else {
            return found;
        };
        let name = |offset: u64| -> Option<String> {
            let from = usize::try_from(table.checked_add(offset)?).ok()?;
            let raw = bytes.get(from..)?;
            let raw = &raw[..raw.len().min(NAME_MAX)];
            let text = raw.split(|b| *b == 0).next()?;
            (!text.is_empty()).then(|| String::from_utf8_lossy(text).into_owned())
        };
        found.needed = needed.into_iter().filter_map(name).collect();
        found.soname = soname.and_then(name);
        found
    }

    /// Whether this is a shared library run as if it were a program: a
    /// shared object (`ET_DYN`) that asks for no interpreter, is not marked
    /// as a PIE and names a library (its own SONAME, or libraries it needs).
    /// A static-PIE program has none of those, and a dynamic PIE has an
    /// interpreter, so neither is taken for a library.
    pub(crate) fn is_shared_library(&self, bytes: &[u8]) -> bool {
        if self.kind != ET_DYN || self.segments.iter().any(|s| s.kind == PT_INTERP) {
            return false;
        }
        let dynamic = self.dynamic(bytes);
        !dynamic.pie && (dynamic.soname.is_some() || !dynamic.needed.is_empty())
    }

    /// The bytes the loadable segments need: the end of the furthest one.
    pub(crate) fn segments_need(&self) -> u64 {
        self.segments
            .iter()
            .filter(|s| s.kind == PT_LOAD)
            .map(|s| s.offset.saturating_add(s.filesz))
            .max()
            .unwrap_or(0)
    }

    /// The sentence for a file that ends before its headers say, or `None`
    /// for a whole one. Loadable segments past the end are the loader's
    /// reason to refuse the file; section headers past the end only hide the
    /// section table.
    pub(crate) fn truncation_note(&self) -> Option<String> {
        let need = self.segments_need();
        if need > self.len {
            return Some(format!(
                "This ELF is truncated: its segments need {}, the file has {}. A partial upload or download; get a full copy.",
                megabytes(need),
                megabytes(self.len)
            ));
        }
        if let Some((_, end)) = self.section_table
            && end > self.len
        {
            return Some(format!(
                "This ELF is truncated: its section headers need {}, the file has {}. A partial upload or download; get a full copy.",
                megabytes(end),
                megabytes(self.len)
            ));
        }
        None
    }

    /// The loader's view of the linking: program headers only.
    pub(crate) fn linking(&self, bytes: &[u8]) -> Linking {
        if let Some(interp) = self.segments.iter().find(|s| s.kind == PT_INTERP) {
            let start = usize::try_from(interp.offset).unwrap_or(usize::MAX);
            let size = usize::try_from(interp.filesz).unwrap_or(0).min(INTERP_MAX);
            if let Some(raw) = bytes.get(start..start.saturating_add(size).min(bytes.len())) {
                let text = raw.split(|b| *b == 0).next().unwrap_or(&[]);
                if !text.is_empty() {
                    return Linking::Interpreter(String::from_utf8_lossy(text).into_owned());
                }
            }
        }
        if self.segments.iter().any(|s| s.kind == PT_DYNAMIC) {
            Linking::DynamicWithoutInterpreter
        } else {
            Linking::Static
        }
    }

    /// File offset of the entry point, when a loadable segment holds it.
    fn entry_offset(&self) -> Option<u64> {
        self.segments
            .iter()
            .filter(|s| s.kind == PT_LOAD && s.filesz > 0)
            .find(|s| self.entry >= s.vaddr && self.entry - s.vaddr < s.filesz)
            .map(|s| s.offset + (self.entry - s.vaddr))
    }

    /// Ways the file ends before its own headers say it does: an empty list
    /// for a whole file. Each is a plain sentence.
    pub(crate) fn truncation(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.table_complete {
            problems.push("the program header table runs past the end of the file".to_owned());
        }
        for (index, s) in self.segments.iter().enumerate() {
            let end = s.offset.saturating_add(s.filesz);
            if s.kind == PT_LOAD && end > self.len {
                problems.push(format!(
                    "loadable segment {index} (address {:#x}) ends {} bytes past the end of the file",
                    s.vaddr,
                    end - self.len
                ));
            }
        }
        if let Some(offset) = self.entry_offset()
            && offset >= self.len
        {
            problems.push(format!(
                "the entry point {:#x} is at file offset {offset:#x}, {} bytes past the end of the file; it would crash with SIGBUS before its first instruction",
                self.entry,
                offset - self.len + 1
            ));
        }
        if let Some((start, end)) = self.section_table
            && end > self.len
        {
            problems.push(if start >= self.len {
                "the section header table is missing (it would be past the end of the file)".into()
            } else {
                "the section header table is cut off at the end of the file".to_owned()
            });
        }
        problems
    }
}

/// Facts about `bytes` that explain why a tool that needs a whole, ordinary
/// program gave up on it, one sentence each; empty when nothing stands out.
pub(crate) fn tool_obstacles(bytes: &[u8]) -> Vec<String> {
    let mut facts = Vec::new();
    let Some(elf) = parse(bytes) else {
        return facts;
    };
    let cut = elf.truncation();
    if !cut.is_empty() {
        facts.push(format!("the file is truncated: {}", cut.join("; ")));
    }
    if elf.section_table.is_none() {
        facts.push("it has no section header table (stripped to the loader's view)".into());
    }
    if bytes.windows(4).any(|w| w == b"UPX!") || bytes.windows(8).any(|w| w == b"$Info: T") {
        facts.push("it carries UPX markers, so it is probably packed".into());
    }
    if elf.linking(bytes) == Linking::Static {
        facts.push("it is statically linked".into());
    }
    facts
}

/// How much of a file's front is read to judge its headers.
const HEAD_MAX: u64 = 256 * 1024;

/// The truncation sentence for the ELF at `path`, reading only its front;
/// `None` for a whole file, a file that is no ELF or one that cannot be read.
pub(crate) fn file_truncation_note(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let mut head = Vec::new();
    file.take(HEAD_MAX).read_to_end(&mut head).ok()?;
    let mut elf = parse(&head)?;
    // The headers were read from the front; the length is the file's.
    elf.len = len;
    elf.truncation_note()
}

/// The notes a file earns from its own headers, one sentence each: a
/// truncated ELF and a shared library run as a program.
pub(crate) fn file_notes(bytes: &[u8]) -> Vec<String> {
    let Some(elf) = parse(bytes) else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    notes.extend(elf.truncation_note());
    if elf.is_shared_library(bytes) {
        notes.push(SHARED_LIBRARY_NOTE.to_owned());
    }
    notes
}

/// The notes a report's Metadata rows carry about the file itself: a
/// truncated ELF, a shared library. Empty for a report made before they
/// existed or for a file with none.
pub fn report_notes(report: &super::AnalysisReport) -> Vec<String> {
    report
        .sections
        .iter()
        .filter(|section| section.kind == super::AnalysisKind::Metadata)
        .flat_map(|section| &section.entries)
        .filter(|entry| entry.label == NOTE_LABEL)
        .map(|entry| entry.value.clone())
        .collect()
}

/// The label of a Metadata row that is a note about the file, not a fact.
pub(crate) const NOTE_LABEL: &str = "Note";

/// The note for a shared library, without a name.
pub(crate) const SHARED_LIBRARY_NOTE: &str = "This is a shared library, not a program; it is meant to be loaded by another process (LD_PRELOAD or dlopen).";

#[cfg(test)]
pub(crate) mod fixtures {
    /// A small x86-64 ELF with one PT_LOAD, `len` bytes of file and the
    /// entry point `entry_in_file` bytes into the file image.
    pub fn elf64(
        file_len: usize,
        load_filesz: u64,
        entry_offset: u64,
        with_interp: bool,
    ) -> Vec<u8> {
        let mut file = vec![0u8; file_len.max(0x200)];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        let base = 0x400000u64;
        file[0x18..0x20].copy_from_slice(&(base + entry_offset).to_le_bytes());
        file[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        file[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        let count: u16 = if with_interp { 2 } else { 1 };
        file[0x38..0x3a].copy_from_slice(&count.to_le_bytes());
        let mut at = 64;
        let mut put = |file: &mut Vec<u8>, kind: u32, offset: u64, vaddr: u64, filesz: u64| {
            file[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            file[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            file[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            file[at + 40..at + 48].copy_from_slice(&filesz.to_le_bytes());
            at += 56;
        };
        if with_interp {
            put(&mut file, 3, 0x180, base + 0x180, 28);
            file[0x180..0x180 + 28].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        }
        put(&mut file, 1, 0, base, load_filesz);
        file
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::elf64;
    use super::*;

    #[test]
    fn a_whole_file_has_no_truncation_and_linking_comes_from_program_headers() {
        let whole = elf64(0x400, 0x400, 0x100, true);
        let elf = parse(&whole).unwrap();
        assert!(elf.truncation().is_empty(), "{:?}", elf.truncation());
        assert_eq!(
            elf.linking(&whole),
            Linking::Interpreter("/lib64/ld-linux-x86-64.so.2".into())
        );
        // No section table at all: the interpreter is still found, which is
        // what `file` reads and a section lookup would miss.
        assert_eq!(elf.section_table, None);
        let fixed = elf64(0x400, 0x400, 0x100, false);
        assert_eq!(parse(&fixed).unwrap().linking(&fixed), Linking::Static);
    }

    #[test]
    fn an_entry_point_and_segment_past_the_end_are_flagged() {
        // The file is 0x300 bytes; the segment says 0x400 and the entry is at 0x350.
        let mut cut = elf64(0x300, 0x400, 0x350, false);
        cut.truncate(0x300);
        let elf = parse(&cut).unwrap();
        let problems = elf.truncation();
        assert!(
            problems.iter().any(|p| p.contains("ends 256 bytes past")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("entry point") && p.contains("SIGBUS")),
            "{problems:?}"
        );
        let facts = tool_obstacles(&cut);
        assert!(facts[0].starts_with("the file is truncated"));
        assert!(parse(b"not an elf").is_none());
        assert!(parse(&cut[..30]).is_none());
    }

    /// A tiny ET_DYN built here: one PT_LOAD over the whole file, a dynamic
    /// section at 0x100 and its string table at 0x200.
    fn shared_object(soname: Option<&str>, needed: &[&str], interp: bool, pie: bool) -> Vec<u8> {
        let mut file = vec![0u8; 0x400];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[0x10..0x12].copy_from_slice(&3u16.to_le_bytes());
        file[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        file[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        let headers: u16 = 2 + u16::from(interp);
        file[0x38..0x3a].copy_from_slice(&headers.to_le_bytes());
        let mut at = 64;
        let mut header = |file: &mut Vec<u8>, kind: u32, offset: u64, filesz: u64| {
            file[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            file[at + 16..at + 24].copy_from_slice(&offset.to_le_bytes());
            file[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            at += 56;
        };
        header(&mut file, 1, 0, 0x400);
        header(&mut file, 2, 0x100, 0x100);
        if interp {
            header(&mut file, 3, 0x300, 8);
            file[0x300..0x306].copy_from_slice(b"/ld.so");
        }
        let mut strings = vec![0u8];
        let entry = |tag: u64, value: u64, at: &mut usize, file: &mut Vec<u8>| {
            file[*at..*at + 8].copy_from_slice(&tag.to_le_bytes());
            file[*at + 8..*at + 16].copy_from_slice(&value.to_le_bytes());
            *at += 16;
        };
        let mut dynamic = 0x100;
        for name in needed {
            entry(1, strings.len() as u64, &mut dynamic, &mut file);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        if let Some(name) = soname {
            entry(14, strings.len() as u64, &mut dynamic, &mut file);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        entry(5, 0x200, &mut dynamic, &mut file);
        if pie {
            entry(0x6fff_fffb, 0x0800_0000, &mut dynamic, &mut file);
        }
        file[0x200..0x200 + strings.len()].copy_from_slice(&strings);
        file
    }

    #[test]
    fn the_truncation_note_says_how_much_the_segments_need_and_the_file_has() {
        // 2.0 MB on disk, segments that reach 30.3 MB.
        let mut cut = elf64(0x400, 30_300_000, 0x100, false);
        cut.truncate(0x400);
        let mut elf = parse(&cut).unwrap();
        elf.len = 2_000_000;
        assert_eq!(
            elf.truncation_note().as_deref(),
            Some(
                "This ELF is truncated: its segments need 30.3 MB, the file has 2.0 MB. A partial upload or download; get a full copy."
            )
        );
        // A whole file says nothing.
        let whole = elf64(0x400, 0x400, 0x100, false);
        assert_eq!(parse(&whole).unwrap().truncation_note(), None);
        assert!(file_notes(&whole).is_empty());
    }

    #[test]
    fn section_headers_past_the_end_are_a_truncation_too() {
        let mut file = elf64(0x400, 0x400, 0x100, false);
        // e_shoff 0x3f0, 4 headers of 64 bytes: the table ends at 0x4f0.
        file[0x28..0x30].copy_from_slice(&0x3f0u64.to_le_bytes());
        file[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        file[0x3c..0x3e].copy_from_slice(&4u16.to_le_bytes());
        let note = parse(&file).unwrap().truncation_note().unwrap();
        assert!(note.contains("section headers need"), "{note}");
    }

    #[test]
    fn needed_libraries_and_the_soname_are_read_from_the_dynamic_section() {
        let file = shared_object(
            Some("libx.so.1"),
            &["libhwloc.so.15", "libc.so.6"],
            false,
            false,
        );
        let dynamic = parse(&file).unwrap().dynamic(&file);
        assert_eq!(dynamic.needed, ["libhwloc.so.15", "libc.so.6"]);
        assert_eq!(dynamic.soname.as_deref(), Some("libx.so.1"));
        assert!(!dynamic.pie);
        // A file with no dynamic segment names nothing.
        let fixed = elf64(0x400, 0x400, 0x100, false);
        assert_eq!(parse(&fixed).unwrap().dynamic(&fixed), Dynamic::default());
    }

    #[test]
    fn a_shared_object_is_told_from_a_pie_and_a_static_pie() {
        // Library: ET_DYN, no interpreter, a SONAME or needed libraries.
        let library = shared_object(Some("exp.so"), &["libc.so.6"], false, false);
        assert!(parse(&library).unwrap().is_shared_library(&library));
        assert_eq!(file_notes(&library), [SHARED_LIBRARY_NOTE]);
        let unnamed = shared_object(None, &["libc.so.6"], false, false);
        assert!(parse(&unnamed).unwrap().is_shared_library(&unnamed));
        // A dynamic PIE program has an interpreter.
        let pie = shared_object(None, &["libc.so.6"], true, false);
        assert!(!parse(&pie).unwrap().is_shared_library(&pie));
        // A PIE the linker marked as one, whatever it needs.
        let marked = shared_object(None, &["libc.so.6"], false, true);
        assert!(!parse(&marked).unwrap().is_shared_library(&marked));
        // A static-PIE: ET_DYN, a dynamic segment, but no SONAME and no libraries.
        let static_pie = shared_object(None, &[], false, false);
        assert!(!parse(&static_pie).unwrap().is_shared_library(&static_pie));
        // A plain executable (ET_EXEC) is never one.
        let exec = elf64(0x400, 0x400, 0x100, false);
        assert!(!parse(&exec).unwrap().is_shared_library(&exec));
    }
}
