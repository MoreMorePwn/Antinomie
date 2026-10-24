// SPDX-License-Identifier: GPL-3.0-only
//! Checks that the dump's symbol table was made for the dump's kernel.
//!
//! MemNixFS takes the release of a table from its metadata name or file name
//! (`vmlinux`, `symbols.json.xz`), never from the table's `linux_banner`, so
//! it calls every Antinomie table a mismatch. The offsets are right when the
//! table's banner text is the one in the dump, which is what is checked here.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

const XZ_MEMORY_LIMIT_KB: u32 = 256 * 1024;
const CHUNK: usize = 16 * 1024 * 1024;

#[derive(serde::Deserialize)]
struct Isf {
    #[serde(default)]
    symbols: HashMap<String, Symbol>,
}

#[derive(serde::Deserialize)]
struct Symbol {
    constant_data: Option<String>,
}

/// The kernel banner text a table carries (`linux_banner`), if it has one.
fn table_banner(symbols: &Path) -> Option<Vec<u8>> {
    let file = File::open(symbols).ok()?;
    let xz = lzma_rust2::XzReader::new_mem_limit(BufReader::new(file), false, XZ_MEMORY_LIMIT_KB);
    let mut isf: Isf = serde_json::from_reader(BufReader::new(xz)).ok()?;
    let data = isf.symbols.remove("linux_banner")?.constant_data?;
    let mut banner = base64(&data)?;
    while banner
        .last()
        .is_some_and(|b| *b == 0 || b.is_ascii_whitespace())
    {
        banner.pop();
    }
    (banner.len() >= 24 && banner.starts_with(b"Linux version ")).then_some(banner)
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

/// Whether `needle` occurs in the file, read in chunks.
fn file_contains(path: &Path, needle: &[u8], stop: &AtomicBool) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut buffer = vec![0u8; CHUNK + needle.len()];
    let mut kept = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let mut filled = kept;
        while filled < buffer.len() {
            match file.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return false,
            }
        }
        let data = &buffer[..filled];
        let mut at = 0;
        while let Some(found) = data[at..].iter().position(|b| *b == needle[0]) {
            let start = at + found;
            if data[start..].starts_with(needle) {
                return true;
            }
            at = start + 1;
        }
        if filled < buffer.len() {
            return false;
        }
        kept = needle.len() - 1;
        buffer.copy_within(filled - kept..filled, 0);
    }
}

type Key = (PathBuf, PathBuf, u64, Option<SystemTime>);

/// Verdicts already reached, so the reports of one dump read the table and
/// scan the dump once.
static VERDICTS: Mutex<Option<HashMap<Key, bool>>> = Mutex::new(None);

/// Whether the table's banner is the dump's kernel banner. False when either
/// cannot be told or the run was stopped, so a warning is never dropped on a
/// guess; only a finished check is remembered.
pub(super) fn matches(symbols: &Path, dump: &Path, stop: &AtomicBool) -> bool {
    let key = std::fs::metadata(dump).ok().map(|meta| {
        (
            symbols.to_path_buf(),
            dump.to_path_buf(),
            meta.len(),
            meta.modified().ok(),
        )
    });
    if let Some(key) = &key
        && let Ok(cache) = VERDICTS.lock()
        && let Some(verdict) = cache.as_ref().and_then(|cache| cache.get(key))
    {
        return *verdict;
    }
    let verdict = table_banner(symbols).is_some_and(|banner| file_contains(dump, &banner, stop));
    if let Some(key) = key
        && !stop.load(Ordering::Relaxed)
        && let Ok(mut cache) = VERDICTS.lock()
    {
        cache.get_or_insert_with(HashMap::new).insert(key, verdict);
    }
    verdict
}
