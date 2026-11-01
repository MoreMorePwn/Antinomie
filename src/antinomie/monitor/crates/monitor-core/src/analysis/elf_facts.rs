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

impl Elf {
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
}
