// SPDX-License-Identifier: GPL-3.0-only
//! What the regex matches window reads: the strings of a Static analysis
//! report (Strings and FLOSS listings) and of a process core, and the
//! `sockaddr_in` and `sockaddr_in6` structures in a core's memory.
use super::{Category, Match, Origin, RuleSet, Scan};
use crate::{
    analysis::{AnalysisData, AnalysisEntry, AnalysisKind},
    core_dump::CoreDump,
    core_strings::CoreString,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Octets read and searched at a time.
const BLOCK: usize = 1 << 20;
/// Socket addresses kept from one core.
const SOCKADDR_MAX_COUNT: usize = 20_000;
/// Size of `struct sockaddr_in6`, the longest one looked for.
const SOCKADDR_MAX_SIZE: usize = 28;

/// Scan the Strings and FLOSS strings of a retained report.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory`, `report_id` | The report's retained folder and its identity. |
/// | `rules` | The patterns to look for. |
/// | `cancel` | Checked for each string; a set flag ends the scan early. |
///
/// Call on a background thread: a listing is read whole.
pub fn scan_report(
    directory: &Path,
    report_id: &str,
    rules: &RuleSet,
    cancel: &AtomicBool,
) -> Result<Scan, String> {
    let report = crate::analysis::open_report(directory)?;
    if report.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    let mut scan = Scan::default();
    for kind in [AnalysisKind::Strings, AnalysisKind::Floss] {
        let Some(section) = report.sections.iter().find(|s| s.kind == kind) else {
            continue;
        };
        let mut each = |entry: &AnalysisEntry| {
            if cancel.load(Ordering::Relaxed) {
                scan.cancelled = true;
                return false;
            }
            let (origin, text) = row(entry);
            rules.scan_text(text, &origin, &mut scan);
            false
        };
        if section.listing.is_some() {
            crate::analysis::read_listing_page_with(
                directory, report_id, kind, 0, 0, "", &mut each,
            )?;
        } else {
            section.entries.iter().for_each(|entry| {
                each(entry);
            });
        }
    }
    Ok(scan)
}

/// Where a listing row's text was found, and the text.
fn row(entry: &AnalysisEntry) -> (Origin, &str) {
    let record = entry.record.as_ref();
    let position = || {
        record
            .and_then(|record| record.location.as_ref())
            .filter(|location| location.kind == crate::analysis::AnalysisAddressKind::FileOffset)
            .map(|location| location.value)
            .or(entry.offset)
    };
    match record.map(|record| &record.data) {
        Some(AnalysisData::FlossString {
            origin, encoding, ..
        }) => (
            Origin {
                label: format!("FLOSS {origin}"),
                position: position().filter(|_| origin == "language"),
                unit: if encoding.starts_with("UTF-16") { 2 } else { 1 },
                space: "offset",
            },
            &entry.value,
        ),
        Some(AnalysisData::String { encoding, .. }) => (
            Origin {
                label: "Strings".into(),
                position: position(),
                unit: if encoding.starts_with("UTF-16") { 2 } else { 1 },
                space: "offset",
            },
            &entry.value,
        ),
        _ => (
            Origin {
                label: "Strings".into(),
                position: position(),
                unit: 1,
                space: "offset",
            },
            &entry.value,
        ),
    }
}

/// Scan the strings found in a core's memory.
pub fn scan_core(strings: &[CoreString], rules: &RuleSet, cancel: &AtomicBool) -> Scan {
    let mut scan = Scan::default();
    for string in strings {
        if cancel.load(Ordering::Relaxed) {
            scan.cancelled = true;
            break;
        }
        let origin = Origin {
            label: "Core strings".into(),
            position: Some(string.address),
            unit: if string.encoding == "UTF-16LE" { 2 } else { 1 },
            space: "address",
        };
        rules.scan_text(&string.text, &origin, &mut scan);
    }
    scan
}

/// A socket address structure found in a core's memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SockAddr {
    /// Virtual address of the structure.
    pub address: u64,
    pub ip: IpAddr,
    pub port: u16,
}

impl Scan {
    /// Add the socket addresses of a core as Network matches.
    pub fn add_sockaddrs(&mut self, found: &[SockAddr]) {
        for sock in found {
            let (kind, text) = match sock.ip {
                IpAddr::V4(ip) => (
                    format!("sockaddr_in ({})", super::checks::ipv4_class(ip)),
                    format!("{ip}:{}", sock.port),
                ),
                IpAddr::V6(ip) => ("sockaddr_in6".to_owned(), format!("[{ip}]:{}", sock.port)),
            };
            self.add(Match {
                rule: "net.sockaddr".into(),
                category: Category::Network,
                kind,
                text,
                origin: "Core memory".into(),
                position: Some(sock.address),
                space: "address",
                via: Vec::new(),
                note: "binary socket address, not a string".into(),
                repeats: 0,
            });
        }
    }
}

/// Find the `sockaddr_in` and `sockaddr_in6` structures in the captured
/// memory of `core`: the family, a port, an address that is not all zero and
/// the zero padding the kernel's structures have.
///
/// | Argument | Meaning |
/// |---|---|
/// | `core` | An opened core; its file is read in blocks. |
/// | `cancel` | Checked once per block. |
/// | `progress` | Receives the captured octets searched so far. |
///
/// Call on a background thread: a large core takes a while.
pub fn sockaddrs(
    core: &CoreDump,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> std::io::Result<Vec<SockAddr>> {
    let mut file = File::open(&core.source)?;
    let file_size = file.metadata()?.len();
    let mut found = Vec::new();
    let mut scanned = 0u64;
    let mut buffer = Vec::new();
    for mapping in &core.mappings {
        let available = mapping
            .available_size
            .min(mapping.memory_size)
            .min(file_size.saturating_sub(mapping.file_offset));
        let mut position = 0u64;
        while position < available {
            if cancel.load(Ordering::Relaxed) {
                return Ok(found);
            }
            // A structure at the end of a block is read whole from beyond it.
            let length = (available - position).min((BLOCK + SOCKADDR_MAX_SIZE) as u64) as usize;
            buffer.resize(length, 0);
            file.seek(SeekFrom::Start(mapping.file_offset + position))?;
            if file.read_exact(&mut buffer).is_err() {
                break;
            }
            let step = length.min(BLOCK);
            for at in (0..step).step_by(2) {
                if let Some((ip, port)) = sockaddr_at(&buffer[at..]) {
                    if found.len() >= SOCKADDR_MAX_COUNT {
                        return Ok(found);
                    }
                    found.push(SockAddr {
                        address: mapping.start + position + at as u64,
                        ip,
                        port,
                    });
                }
            }
            scanned += step as u64;
            progress.store(scanned, Ordering::Relaxed);
            position += step as u64;
        }
    }
    Ok(found)
}

/// The address and port of a socket address structure at the start of `bytes`.
fn sockaddr_at(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    match bytes {
        // AF_INET: family, port (network order), address, eight zero octets.
        [2, 0, p0, p1, a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, ..] => {
            let port = u16::from_be_bytes([*p0, *p1]);
            let ip = Ipv4Addr::new(*a, *b, *c, *d);
            (port != 0 && *a != 0 && *a != 255 && !ip.is_multicast()).then_some((ip.into(), port))
        }
        // AF_INET6: family, port, flow information 0, address, scope id.
        [10, 0, p0, p1, 0, 0, 0, 0, rest @ ..] if rest.len() >= 20 => {
            let port = u16::from_be_bytes([*p0, *p1]);
            let octets: [u8; 16] = rest[..16].try_into().ok()?;
            let ip = Ipv6Addr::from(octets);
            let scope = u32::from_le_bytes(rest[16..20].try_into().ok()?);
            (port != 0 && !ip.is_unspecified() && !ip.is_multicast() && scope <= 0xffff)
                .then_some((ip.into(), port))
        }
        _ => None,
    }
}
