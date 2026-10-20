//! Network capture: while a capture runs, QEMU writes every frame of a NAT
//! VM's network interface to a pcap file in the boot recording (a filter-dump
//! object added over QMP, outside the guest). Each capture is
//! `boots/<boot>/network/<capture>.pcap` with a small JSON summary beside it;
//! boots recorded before captures were started by hand have one
//! `boots/<boot>/network.pcap` covering the whole boot.
//! The packet list and details are TShark's (see `packet_filter`); this module
//! lists the captures, reads their raw frames, and builds the QEMU commands.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    net::IpAddr,
    path::{Path, PathBuf},
};

mod pcap;

pub use self::pcap::*;

/// File name of a whole-boot network capture (boots before 0.3.0 recorded
/// network traffic for as long as the VM ran).
pub const PCAP_FILE: &str = "network.pcap";
/// Folder of a boot recording that holds its network captures.
pub const CAPTURE_DIR: &str = "network";
/// Bytes of one frame kept by QEMU (maxlen) and accepted when reading.
const MAX_FRAME: u32 = 65_535;
/// TCP header flags, as in [`NetworkPacket::tcp_flags`].
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;

/// One network capture of a boot: a pcap file and when it ran.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCapture {
    pub id: String,
    pub boot_id: String,
    /// The pcap file. The saved summary names it relative to its folder.
    pub file: PathBuf,
    /// Wall clock, milliseconds since the Unix epoch.
    pub started_ms: u64,
    /// `None` while the capture runs (or when the app ended before it could
    /// write the stop).
    pub stopped_ms: Option<u64>,
    /// Packets and file size, counted when the capture stopped.
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    /// A whole-boot capture from before captures were started by hand.
    pub whole_boot: bool,
}

impl NetworkCapture {
    /// A new capture in the boot recording `boot_dir`.
    pub fn new(boot_dir: &Path, boot_id: &str, id: &str, started_ms: u64) -> Self {
        NetworkCapture {
            id: id.into(),
            boot_id: boot_id.into(),
            file: boot_dir.join(CAPTURE_DIR).join(format!("{id}.pcap")),
            started_ms,
            ..NetworkCapture::default()
        }
    }

    /// The summary file beside the pcap.
    pub fn summary_path(&self) -> PathBuf {
        self.file.with_extension("json")
    }

    /// The QEMU object that writes this capture.
    pub fn object_id(&self) -> String {
        // QOM ids start with a letter.
        format!("netdump-{}", self.id)
    }
}

/// QMP command that starts writing `capture` from the VM's `net0` interface.
pub fn filter_dump_add(capture: &NetworkCapture) -> Result<serde_json::Value, String> {
    let file = capture
        .file
        .to_str()
        .ok_or("network capture path is not UTF-8")?;
    Ok(serde_json::json!({
        "execute": "object-add",
        "arguments": {
            "qom-type": "filter-dump",
            "id": capture.object_id(),
            "netdev": "net0",
            "file": file,
            "maxlen": MAX_FRAME,
        }
    }))
}

/// QMP command that stops `capture` (QEMU closes the file).
pub fn filter_dump_del(capture: &NetworkCapture) -> serde_json::Value {
    serde_json::json!({"execute": "object-del", "arguments": {"id": capture.object_id()}})
}

/// Queue `capture`'s summary for saving beside its pcap. The persistence
/// thread publishes it, so the caller never waits for an `fsync`; a failure
/// shows at the next save of the same summary.
pub(crate) fn save_summary(capture: &NetworkCapture) -> Result<(), String> {
    let mut saved = capture.clone();
    saved.file = capture
        .file
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_default();
    crate::storage::queue_json(&capture.summary_path(), &saved)
}

/// Every network capture in a VM's recording folder, newest first: the
/// captures of each boot and the whole-boot captures of older boots.
pub fn list_captures(recordings: &Path) -> Vec<NetworkCapture> {
    let mut found = Vec::new();
    for boot in std::fs::read_dir(recordings.join("boots"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if !boot.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let boot_dir = boot.path();
        let boot_id = boot.file_name().to_string_lossy().into_owned();
        let whole = boot_dir.join(PCAP_FILE);
        if let Ok(file) = crate::archive_io::open_regular(&boot_dir, &whole)
            && let Ok(metadata) = file.metadata()
        {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |time| time.as_millis() as u64);
            let first = read_page(&whole, 0, 0, 1)
                .ok()
                .and_then(|page| page.packets.first().map(|p| p.time_us / 1000));
            found.push(NetworkCapture {
                id: boot_id.clone(),
                boot_id: boot_id.clone(),
                file: whole,
                started_ms: first.unwrap_or(modified),
                stopped_ms: Some(modified),
                packets: None,
                bytes: Some(metadata.len()),
                whole_boot: true,
            });
        }
        let dir = boot_dir.join(CAPTURE_DIR);
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(summary) = crate::archive_io::open_regular(&dir, &path) else {
                continue;
            };
            let Ok(mut capture) =
                serde_json::from_reader::<_, NetworkCapture>(summary.take(65_536))
            else {
                continue;
            };
            // Summaries store a single file name, never an imported absolute
            // path or a traversal into another capture's recording.
            if capture.file.components().count() != 1
                || !matches!(
                    capture.file.components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                continue;
            }
            capture.file = dir.join(&capture.file);
            if capture.boot_id.is_empty() {
                capture.boot_id = boot_id.clone();
            }
            if crate::archive_io::open_regular(&dir, &capture.file).is_ok() {
                found.push(capture);
            }
        }
    }
    found.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    found
}

/// The transport a TCP or UDP port in a packet row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPacket {
    /// Position in the capture, from 1.
    pub number: u64,
    /// File offset of the pcap record, for [`frame`].
    pub offset: u64,
    /// Capture time, microseconds since the Unix epoch (host clock).
    pub time_us: u64,
    /// Length on the wire and bytes captured.
    pub length: u32,
    pub captured: u32,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    /// IP addresses and TCP/UDP ports, when the frame carries them.
    #[serde(default)]
    pub src_ip: Option<IpAddr>,
    #[serde(default)]
    pub dst_ip: Option<IpAddr>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// TCP header flags (`TCP_SYN`, ...), for TCP segments.
    #[serde(default)]
    pub tcp_flags: Option<u8>,
    #[serde(default)]
    pub transport: Option<Transport>,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkPage {
    pub packets: Vec<NetworkPacket>,
    /// Where the next read starts; equal to the file size at the end.
    pub next_offset: u64,
    pub next_number: u64,
}

#[cfg(test)]
mod tests;
