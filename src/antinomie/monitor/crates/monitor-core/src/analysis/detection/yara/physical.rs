// SPDX-License-Identifier: GPL-3.0-only
//! Bounded PT_LOAD inspection for QEMU's x86-64 physical ELF dumps.
//! CPU notes are intentionally not interpreted as Linux process metadata.
use crate::core_dump::CoreMapping;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

const HEADER_LIMIT: u16 = 16_384;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn number<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid("truncated physical dump metadata"))
}

/// Reads only the ELF header and a bounded program-header table from this handle.
pub(super) fn mappings(file: &mut File) -> io::Result<Vec<CoreMapping>> {
    let source_size = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0; 64];
    file.read_exact(&mut header)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes(number(&header, 16)?) != 4
        || u16::from_le_bytes(number(&header, 18)?) != 62
    {
        return Err(invalid(
            "requires an x86-64 little-endian ELF physical dump",
        ));
    }
    let offset = u64::from_le_bytes(number(&header, 32)?);
    let stride = u16::from_le_bytes(number(&header, 54)?);
    let count = u16::from_le_bytes(number(&header, 56)?);
    if stride < 56 || count == 0 || count > HEADER_LIMIT {
        return Err(invalid("unsupported physical dump program-header table"));
    }
    let end = offset
        .checked_add(u64::from(stride) * u64::from(count))
        .ok_or_else(|| invalid("physical dump program-header overflow"))?;
    if end > source_size {
        return Err(invalid("truncated physical dump program-header table"));
    }
    let mut mappings = Vec::new();
    for index in 0..count {
        file.seek(SeekFrom::Start(
            offset + u64::from(index) * u64::from(stride),
        ))?;
        let mut ph = [0; 56];
        file.read_exact(&mut ph)?;
        if u32::from_le_bytes(number(&ph, 0)?) != 1 {
            continue;
        }
        let file_offset = u64::from_le_bytes(number(&ph, 8)?);
        let start = u64::from_le_bytes(number(&ph, 24)?);
        let captured_size = u64::from_le_bytes(number(&ph, 32)?);
        let memory_size = u64::from_le_bytes(number(&ph, 40)?);
        file_offset
            .checked_add(captured_size)
            .ok_or_else(|| invalid("physical dump file extent overflow"))?;
        start
            .checked_add(memory_size)
            .ok_or_else(|| invalid("physical dump address overflow"))?;
        if captured_size > memory_size {
            return Err(invalid("physical PT_LOAD file size exceeds memory extent"));
        }
        if memory_size > 0 {
            mappings.push(CoreMapping {
                start,
                memory_size,
                file_offset,
                captured_size,
                available_size: captured_size.min(source_size.saturating_sub(file_offset)),
                flags: u32::from_le_bytes(number(&ph, 4)?),
            });
        }
    }
    mappings.sort_by_key(|mapping| mapping.start);
    if mappings.is_empty() {
        return Err(invalid("physical dump contains no RAM PT_LOAD extents"));
    }
    if mappings
        .windows(2)
        .any(|pair| pair[0].end() > pair[1].start)
    {
        return Err(invalid("overlapping physical RAM extents"));
    }
    Ok(mappings)
}

#[cfg(test)]
mod tests;
