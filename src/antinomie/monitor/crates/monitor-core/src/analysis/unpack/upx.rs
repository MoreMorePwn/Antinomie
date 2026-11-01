// SPDX-License-Identifier: GPL-3.0-only
//! UPX: telling a UPX-packed file from other files, mending the header
//! changes that make `upx -d` refuse one, and running `upx -d` on a copy.
//!
//! UPX never runs the packed program to unpack it; `upx -d` decompresses the
//! file's data. A packed ELF has, right after its program headers, UPX's
//! `l_info` (a checksum, the magic `UPX!`, a size, the version and the format)
//! and, near its end, the pack header (the magic again, the same version and
//! format, the method, level and sizes) with an overlay offset after it. Packed
//! files in the wild often have the magic overwritten or data appended, which
//! stops `upx -d` while the compressed data is intact; that is what is mended.
use super::super::tools;
use std::{fs, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

const MAGIC: &[u8; 4] = b"UPX!";
/// Size of the pack header and the overlay offset that follows it.
const TRAILER_SIZE: usize = 36;
/// How far from the end of the file the pack header is looked for.
const TRAILER_SEARCH_SIZE: usize = 4 * 1024 * 1024;
/// Largest decompressed size a pack header may announce.
const UNPACKED_MAX_SIZE: u32 = 1 << 28;

/// Where an ELF's UPX structures are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layout {
    /// Offset of `l_info`; the magic is 4 octets in.
    pub l_info: usize,
    /// Offset of the pack header.
    pub header: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Detection {
    /// UPX's structures, for an ELF.
    pub layout: Option<Layout>,
    /// What was changed from a file UPX wrote: the magic, data after the end.
    pub changes: Vec<String>,
}

impl Detection {
    /// "UPX", or "UPX (header modified)".
    pub(super) fn label(&self) -> String {
        if self.changes.is_empty() {
            "UPX".into()
        } else {
            "UPX (header modified)".into()
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Offset of `l_info` in a little-endian ELF: right after the program headers.
fn l_info_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..4)? != b"\x7fELF" || *bytes.get(5)? != 1 {
        return None;
    }
    let (offset, size, count) = match *bytes.get(4)? {
        2 => (
            usize::try_from(u64::from_le_bytes(bytes.get(0x20..0x28)?.try_into().ok()?)).ok()?,
            u16_at(bytes, 0x36)?,
            u16_at(bytes, 0x38)?,
        ),
        1 => (
            u32_at(bytes, 0x1c)? as usize,
            u16_at(bytes, 0x2a)?,
            u16_at(bytes, 0x2c)?,
        ),
        _ => return None,
    };
    let end = offset.checked_add(usize::from(size).checked_mul(usize::from(count))?)?;
    (usize::from(count) > 0 && end.checked_add(12)? <= bytes.len()).then_some(end)
}

/// The pack header of an ELF whose `l_info` is at `l_info`: the last place
/// whose version and format octets are `l_info`'s and whose sizes are
/// plausible, wherever the magic is.
fn find_header(bytes: &[u8], l_info: usize) -> Option<usize> {
    let (version, format) = (bytes[l_info + 10], bytes[l_info + 11]);
    let last = bytes.len().checked_sub(TRAILER_SIZE)?;
    let first = l_info
        .saturating_add(24)
        .max(bytes.len().saturating_sub(TRAILER_SEARCH_SIZE));
    (first..=last).rev().find(|&at| {
        bytes[at + 4] == version
            && bytes[at + 5] == format
            && bytes[at + 6] <= 15
            && (1..=10).contains(&bytes[at + 7])
            && matches!(
                (u32_at(bytes, at + 16), u32_at(bytes, at + 20)),
                (Some(unpacked), Some(packed))
                    if (1..=UNPACKED_MAX_SIZE).contains(&unpacked)
                        && packed as usize <= at
                        && packed as usize + 0x2000 >= at
            )
    })
}

/// The pack header when the packer's author altered its version or format
/// octets (so they no longer match `l_info`'s): the last `UPX!` magic whose
/// sizes are still plausible.
fn find_header_loose(bytes: &[u8], l_info: usize) -> Option<usize> {
    let last = bytes.len().checked_sub(TRAILER_SIZE)?;
    let first = l_info
        .saturating_add(24)
        .max(bytes.len().saturating_sub(TRAILER_SEARCH_SIZE));
    (first..=last).rev().find(|&at| {
        bytes[at..at + 4] == *MAGIC
            && matches!(
                (u32_at(bytes, at + 16), u32_at(bytes, at + 20)),
                (Some(unpacked), Some(packed))
                    if (1..=UNPACKED_MAX_SIZE).contains(&unpacked)
                        && packed as usize <= at
                        && packed as usize + 0x2000 >= at
            )
    })
}

/// A sign of UPX anywhere in the file, for a file whose structures are too
/// damaged to unpack: the packer's `$Info:` line, or a `UPX!` magic.
pub(super) fn marker(bytes: &[u8]) -> Option<&'static str> {
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    if has(b"$Info: This file is packed with the UPX") {
        Some("the UPX copyright line")
    } else if bytes.windows(4).filter(|w| *w == MAGIC).count() >= 2 {
        // The loader header and the pack header each carry the magic; one
        // occurrence is as likely to be text in an unrelated program.
        Some("the UPX! magic in both of UPX's headers")
    } else {
        None
    }
}

/// Whether `bytes` is a file UPX packed, with what is amiss in it.
pub(super) fn detect(bytes: &[u8]) -> Option<Detection> {
    if let Some(l_info) = l_info_offset(bytes) {
        let (header, altered) = match find_header(bytes, l_info) {
            Some(header) => (header, false),
            None => (find_header_loose(bytes, l_info)?, true),
        };
        let layout = Layout { l_info, header };
        let mut changes = Vec::new();
        if altered {
            changes.push(
                "the version or format in the pack header does not match the loader header"
                    .to_owned(),
            );
        }
        if bytes[l_info + 4..l_info + 8] != *MAGIC {
            changes.push("the magic in the loader header was overwritten".to_owned());
        }
        if bytes[header..header + 4] != *MAGIC {
            changes.push("the magic in the pack header was overwritten".to_owned());
        }
        let extra = bytes.len() - (header + TRAILER_SIZE);
        if extra > 0 {
            changes.push(format!("{extra} octets follow the pack header"));
        }
        return Some(Detection {
            layout: Some(layout),
            changes,
        });
    }
    // A PE UPX packed names its first two sections UPX0 and UPX1.
    let head = bytes.get(..bytes.len().min(2048))?;
    let has = |name: &[u8]| head.windows(name.len()).any(|window| window == name);
    (head.starts_with(b"MZ") && has(b"UPX0") && has(b"UPX1")).then(|| Detection {
        layout: None,
        changes: Vec::new(),
    })
}

/// The file as UPX wrote it: the magic restored, nothing after the pack header.
pub(super) fn repaired(bytes: &[u8], layout: Layout) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[layout.l_info + 4..layout.l_info + 8].copy_from_slice(MAGIC);
    out[layout.header..layout.header + 4].copy_from_slice(MAGIC);
    if layout.header >= 8 && out[layout.header - 4..layout.header] == [0; 4] {
        out[layout.header - 8..layout.header - 4].copy_from_slice(MAGIC);
    }
    out.truncate(layout.header + TRAILER_SIZE);
    out
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Beyond [`repaired`]: the loader's `p_info` (original size, block size)
/// that a packer's author zeroed or damaged is rebuilt from the pack header's
/// sizes, and the pack header's version and format are taken from `l_info`.
/// `checksum` also recomputes the pack header's last octet. Returns the file
/// and what was changed; the list is empty when nothing needed it.
pub(super) fn repaired_deep(
    bytes: &[u8],
    layout: Layout,
    checksum: bool,
) -> (Vec<u8>, Vec<String>) {
    let mut out = repaired(bytes, layout);
    let mut done = Vec::new();
    let (l_info, header) = (layout.l_info, layout.header);
    // Version and format octets of the pack header follow l_info's.
    for (at, from) in [(4usize, 10usize), (5, 11)] {
        if out[header + at] != out[l_info + from] {
            out[header + at] = out[l_info + from];
            if !done.iter().any(|d: &String| d.contains("version")) {
                done.push(
                    "the pack header's version and format were set from the loader header"
                        .to_owned(),
                );
            }
        }
    }
    let file_size = u32_at(&out, header + 24).unwrap_or(0);
    let p_filesize = u32_at(&out, l_info + 16).unwrap_or(0);
    let p_blocksize = u32_at(&out, l_info + 20).unwrap_or(0);
    if file_size > 0
        && (p_filesize == 0
            || p_blocksize == 0
            || p_blocksize > p_filesize
            || p_filesize > file_size.saturating_mul(2))
    {
        out[l_info + 16..l_info + 20].copy_from_slice(&file_size.to_le_bytes());
        out[l_info + 20..l_info + 24].copy_from_slice(&file_size.to_le_bytes());
        done.push(format!(
            "the loader's size record (p_info) was rebuilt from the pack header's {file_size} octets"
        ));
    }
    if checksum {
        let sum = (adler32(&out[header + 4..header + 31]) % 251 + 1) as u8;
        if out[header + 31] != sum {
            out[header + 31] = sum;
            done.push("the pack header checksum was recomputed".to_owned());
        }
    }
    (out, done)
}

pub(super) struct Unpacked {
    pub bytes: Vec<u8>,
    /// What had to be mended for UPX to take the file.
    pub mended: Vec<String>,
}

/// Run `upx -d` on a copy of `bytes` in `work`, mending the file first when
/// plain `upx -d` refuses it. The copies are removed again; the unpacked
/// octets are returned.
pub(super) fn unpack(
    upx: &str,
    bytes: &[u8],
    found: &Detection,
    work: &Path,
    number: usize,
    timeout: Duration,
    max_size: u64,
) -> Result<Unpacked, String> {
    let mut attempts: Vec<(Vec<u8>, Vec<String>)> = vec![(bytes.to_vec(), Vec::new())];
    if let Some(layout) = found.layout {
        // A file with changes goes mended first; any other is mended when UPX
        // refuses it, for what shows only to UPX itself (the marker before
        // the pack header).
        let mended = if found.changes.is_empty() {
            vec!["the UPX headers were restored".to_owned()]
        } else {
            found.changes.clone()
        };
        if found.changes.is_empty() {
            attempts.push((repaired(bytes, layout), mended));
        } else {
            attempts.insert(0, (repaired(bytes, layout), mended));
        }
        // What upx -d still refuses after that: the size record and header
        // fields a packer's author damaged on purpose, then the checksum.
        for checksum in [false, true] {
            let (deep, done) = repaired_deep(bytes, layout, checksum);
            if !done.is_empty() && attempts.iter().all(|(seen, _)| *seen != deep) {
                let mut notes = found.changes.clone();
                notes.extend(done);
                attempts.push((deep, notes));
            }
        }
    }
    let mut last = String::new();
    for (position, (candidate, mended)) in attempts.into_iter().enumerate() {
        let input = work.join(format!("in-{number}-{position}.bin"));
        let output = work.join(format!("out-{number}-{position}.bin"));
        let result = run_once(upx, &candidate, &input, &output, timeout, max_size);
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
        match result {
            Ok(unpacked) => {
                return Ok(Unpacked {
                    bytes: unpacked,
                    mended,
                });
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn run_once(
    upx: &str,
    bytes: &[u8],
    input: &Path,
    output: &Path,
    timeout: Duration,
    max_size: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Write;
    // Not executable: a layer is data, whatever the packed file's mode.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(input)
        .map_err(|e| format!("unpack copy: {e}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("unpack copy: {e}"))?;
    drop(file);
    let (input_text, output_text) = (
        input.to_str().ok_or("unpack path is not text")?,
        output.to_str().ok_or("unpack path is not text")?,
    );
    let run = tools::run_with(
        upx,
        &["-d", "-q", "-o", output_text, input_text],
        &[],
        timeout,
        64 * 1024,
        true,
    )?;
    if let Some(failure) = run.failure_text("UPX", timeout) {
        return Err(failure);
    }
    let size = fs::metadata(output)
        .map_err(|_| "UPX wrote no file".to_owned())?
        .len();
    if size == 0 || size > max_size {
        return Err(format!(
            "UPX unpacked to {size} octets; layers are kept up to {} MiB",
            max_size >> 20
        ));
    }
    fs::read(output).map_err(|e| format!("unpacked file: {e}"))
}
