// SPDX-License-Identifier: GPL-3.0-only
//! The symbol table saved with a dump, named for its kernel's release.
//!
//! dwarf2json names the table's sources `vmlinux`, and MemNixFS and Volatility
//! take the kernel release from that name, so every table of a base reads as a
//! different kernel than the dump's banner and MemNixFS warns of a mismatch.
//! The copy kept with a dump carries the release of the table's own
//! `linux_banner` instead.
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    path::Path,
};

/// Larger than this is not a Linux symbol table of a base.
const LIMIT: u64 = 1 << 30;
/// The metadata is at the start of the table.
const HEAD: usize = 8192;

/// The release in the table's `linux_banner`, from its decoded JSON.
fn release(table: &[u8]) -> Option<String> {
    let at = table
        .windows(14)
        .position(|window| window == b"\"linux_banner\"")?;
    let region = &table[at..(at + 1024).min(table.len())];
    let key = b"\"constant_data\"";
    let start = region.windows(key.len()).position(|window| window == key)? + key.len();
    let rest = &region[start..];
    let open = rest.iter().position(|&byte| byte == b'"')? + 1;
    let text: Vec<u8> = rest[open..]
        .iter()
        .copied()
        .take_while(|&byte| byte != b'"')
        .take(64)
        .collect();
    let mut bytes = Vec::new();
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in text.iter().take(text.len() / 4 * 4) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    let banner = String::from_utf8(bytes).ok()?;
    let name = banner.strip_prefix("Linux version ")?.split(' ').next()?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._~".contains(&byte)))
    .then(|| name.to_owned())
}

/// Copy the xz-compressed table `from` to `to` with the kernel's release in
/// the metadata's names; the table is copied as it is when it has no banner
/// or no `vmlinux` name to replace.
pub(super) fn copy(from: &Path, to: &Path) -> Result<(), String> {
    let plain = || {
        std::fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| format!("symbol table: {e}"))
    };
    let Ok(file) = File::open(from) else {
        return plain();
    };
    let mut table = Vec::new();
    let reader = lzma_rust2::XzReader::new_mem_limit(BufReader::new(file), false, 256 * 1024);
    if reader.take(LIMIT).read_to_end(&mut table).is_err() {
        return plain();
    }
    let Some(release) = release(&table) else {
        return plain();
    };
    let head = table.len().min(HEAD);
    let (start, rest) = table.split_at(head);
    let Ok(named) = std::str::from_utf8(start) else {
        return plain();
    };
    if !named.contains("\"metadata\"") || !named.contains("\"name\": \"vmlinux\"") {
        return plain();
    }
    let patched = named.replace("\"name\": \"vmlinux\"", &format!("\"name\": \"{release}\""));
    let write = || -> std::io::Result<()> {
        let output = File::create(to)?;
        let mut xz = lzma_rust2::XzWriter::new(output, lzma_rust2::XzOptions::with_preset(1))?;
        xz.write_all(patched.as_bytes())?;
        xz.write_all(rest)?;
        xz.finish()?.sync_all()
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(to);
        format!("symbol table: {e}")
    })
}
