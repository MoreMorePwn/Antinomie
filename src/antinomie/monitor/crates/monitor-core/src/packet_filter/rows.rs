// SPDX-License-Identifier: GPL-3.0-only
//! The packet list as TShark printed it, kept on disk.
//!
//! One TShark pass over a capture prints, for every frame, the columns
//! Wireshark shows (Source, Destination, Protocol, Info) and a few fields the
//! list needs for its colors and filter menus. Each row is validated (the
//! output is untrusted), sanitized and appended to `rows.tsv`; `rows.idx`
//! holds the byte offset of every row so a page of any frame numbers is a few
//! seeks. Nothing here interprets a protocol: the strings are TShark's.
use super::*;
use crate::network::{NetworkPacket, Transport};

/// Printable text kept per column (longer values are cut at a character).
const MAX_COLUMN_LEN: usize = 256;
const MAX_INFO_LEN: usize = 1024;
/// One TShark record (a row, or a row with quoted line breaks) is bounded.
pub(super) const MAX_RECORD_SIZE: usize = 65_536;
/// The most row text kept for one capture.
pub(super) const MAX_ROWS_SIZE: u64 = 1024 * 1024 * 1024;
const STORED_COLUMNS: usize = 14;

/// TShark fields printed for every frame, in output order.
pub(super) const ROW_FIELDS: [&str; 17] = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "_ws.col.def_src",
    "_ws.col.def_dst",
    "_ws.col.protocol",
    "_ws.col.info",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "tcp.flags",
];

/// Replace control characters and cut `text` to `limit` characters.
pub(super) fn clean(text: &str, limit: usize) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(limit)
        .collect()
}

/// `1792486878.542435000` as microseconds.
fn epoch_us(text: &str) -> Option<u64> {
    let (seconds, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 12 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut micros: String = fraction.chars().take(6).collect();
    while micros.len() < 6 {
        micros.push('0');
    }
    seconds
        .parse::<u64>()
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(micros.parse().ok()?)
}

fn first_of<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

/// A row from the 17 values TShark printed (see [`ROW_FIELDS`]), or why the
/// output cannot be trusted.
pub(super) fn from_tshark(values: &[String]) -> Result<NetworkPacket, String> {
    if values.len() != ROW_FIELDS.len() {
        return Err(format!(
            "TShark printed {} values for a packet, expected {}",
            values.len(),
            ROW_FIELDS.len()
        ));
    }
    let number = values[0]
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .ok_or("TShark printed an invalid frame number")?;
    let length = values[2]
        .parse::<u32>()
        .map_err(|_| "TShark printed an invalid frame length")?;
    let captured = values[3]
        .parse::<u32>()
        .map_err(|_| "TShark printed an invalid captured length")?;
    let tcp_port = |at: usize| values[at].parse::<u16>().ok();
    let tcp = tcp_port(12).or(tcp_port(14)).is_some() || !values[16].is_empty();
    let src_port = tcp_port(12).or_else(|| tcp_port(13));
    let dst_port = tcp_port(14).or_else(|| tcp_port(15));
    let transport = match (tcp, src_port.is_some() || dst_port.is_some()) {
        (true, _) => Some(Transport::Tcp),
        (false, true) => Some(Transport::Udp),
        _ => None,
    };
    let tcp_flags = values[16]
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .map(|flags| (flags & 0xff) as u8);
    Ok(NetworkPacket {
        number,
        offset: 0,
        time_us: epoch_us(&values[1]).unwrap_or(0),
        length,
        captured,
        source: clean(&values[4], MAX_COLUMN_LEN),
        destination: clean(&values[5], MAX_COLUMN_LEN),
        protocol: clean(&values[6], MAX_COLUMN_LEN),
        info: clean(&values[7], MAX_INFO_LEN),
        src_ip: first_of(&values[8], &values[9]).parse().ok(),
        dst_ip: first_of(&values[10], &values[11]).parse().ok(),
        src_port,
        dst_port,
        transport,
        tcp_flags,
    })
}

/// Split one TShark output record into its quoted values. The record is
/// complete when its quotes balance; a doubled quote is a literal one.
pub(super) fn split_record(record: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::with_capacity(ROW_FIELDS.len());
    let mut value = String::new();
    let mut chars = record.trim_end_matches(['\r', '\n']).chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                value.push('"');
            }
            '"' => quoted = !quoted,
            '\t' if !quoted => values.push(std::mem::take(&mut value)),
            other => value.push(other),
        }
    }
    if quoted {
        return Err("TShark printed an unterminated quoted value".into());
    }
    values.push(value);
    Ok(values)
}

fn encode(packet: &NetworkPacket) -> String {
    let ip = |ip: Option<std::net::IpAddr>| ip.map(|ip| ip.to_string()).unwrap_or_default();
    let port = |port: Option<u16>| port.map(|port| port.to_string()).unwrap_or_default();
    let transport = match packet.transport {
        Some(Transport::Tcp) => "tcp",
        Some(Transport::Udp) => "udp",
        None => "",
    };
    let flags = packet
        .tcp_flags
        .map(|flags| flags.to_string())
        .unwrap_or_default();
    [
        packet.number.to_string(),
        packet.time_us.to_string(),
        packet.length.to_string(),
        packet.captured.to_string(),
        packet.source.clone(),
        packet.destination.clone(),
        packet.protocol.clone(),
        packet.info.clone(),
        ip(packet.src_ip),
        ip(packet.dst_ip),
        port(packet.src_port),
        port(packet.dst_port),
        transport.into(),
        flags,
    ]
    .join("\t")
}

fn decode(line: &str) -> Result<NetworkPacket, String> {
    let columns: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
    if columns.len() != STORED_COLUMNS {
        return Err("the stored packet row is damaged".into());
    }
    let number = |at: usize| {
        columns[at]
            .parse::<u64>()
            .map_err(|_| "the stored packet row is damaged".to_string())
    };
    Ok(NetworkPacket {
        number: number(0)?,
        offset: 0,
        time_us: number(1)?,
        length: number(2)? as u32,
        captured: number(3)? as u32,
        source: columns[4].into(),
        destination: columns[5].into(),
        protocol: columns[6].into(),
        info: columns[7].into(),
        src_ip: columns[8].parse().ok(),
        dst_ip: columns[9].parse().ok(),
        src_port: columns[10].parse().ok(),
        dst_port: columns[11].parse().ok(),
        transport: match columns[12] {
            "tcp" => Some(Transport::Tcp),
            "udp" => Some(Transport::Udp),
            _ => None,
        },
        tcp_flags: columns[13].parse().ok(),
    })
}

/// Where a parse stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseStatus {
    Parsing,
    Complete,
    /// TShark failed, was missing, or output hit a limit; rows already
    /// stored stay readable.
    Failed(String),
}

/// Rows of one capture, written by a parse thread and read by pages.
pub struct RowStore {
    dir: PathBuf,
    /// Keeps a temporary directory alive; a cached store is not deleted.
    _scratch: Option<Scratch>,
    done_count: AtomicU64,
    total_count: AtomicU64,
    status: Mutex<ParseStatus>,
    pub(super) cancel: Arc<AtomicBool>,
    /// Whether a parse thread currently owns the writer.
    pub(super) running: AtomicBool,
    pub(super) cached: bool,
    /// Whether the cache beside the capture was written from this store.
    pub(super) cache_saved: AtomicBool,
}

impl RowStore {
    pub(super) fn scratch() -> Result<Arc<Self>, String> {
        let scratch = Scratch::new()?;
        scratch.file("rows.tsv")?;
        scratch.file("rows.idx")?;
        Ok(Arc::new(Self {
            dir: scratch.path.clone(),
            _scratch: Some(scratch),
            done_count: AtomicU64::new(0),
            total_count: AtomicU64::new(0),
            status: Mutex::new(ParseStatus::Parsing),
            cancel: Arc::new(AtomicBool::new(false)),
            running: AtomicBool::new(false),
            cached: false,
            cache_saved: AtomicBool::new(false),
        }))
    }

    /// A store that never parsed (its folder could not be made).
    pub(super) fn failed(error: String) -> Arc<Self> {
        Arc::new(Self {
            dir: PathBuf::new(),
            _scratch: None,
            done_count: AtomicU64::new(0),
            total_count: AtomicU64::new(0),
            status: Mutex::new(ParseStatus::Failed(error)),
            cancel: Arc::new(AtomicBool::new(false)),
            running: AtomicBool::new(false),
            cached: false,
            cache_saved: AtomicBool::new(false),
        })
    }

    /// A complete store read from a cache folder (already validated).
    pub(super) fn from_cache(dir: PathBuf, count: u64) -> Arc<Self> {
        Arc::new(Self {
            dir,
            _scratch: None,
            done_count: AtomicU64::new(count),
            total_count: AtomicU64::new(count),
            status: Mutex::new(ParseStatus::Complete),
            cancel: Arc::new(AtomicBool::new(false)),
            running: AtomicBool::new(false),
            cached: true,
            cache_saved: AtomicBool::new(true),
        })
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }
    /// Rows that can be read now.
    pub fn done_count(&self) -> u64 {
        self.done_count.load(Ordering::Acquire)
    }
    /// Frames the running parse will have read when it finishes.
    pub fn total_count(&self) -> u64 {
        self.total_count.load(Ordering::Acquire)
    }
    pub(super) fn set_total(&self, total: u64) {
        self.total_count.store(total, Ordering::Release);
    }
    pub fn status(&self) -> ParseStatus {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub(super) fn set_status(&self, status: ParseStatus) {
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = status;
    }
    /// Stop the parse; rows already stored stay readable.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// The rows of frames `numbers`, which must each be one already parsed
    /// (a number past [`Self::done_count`] ends the result).
    pub(super) fn read(&self, numbers: &[u64]) -> Result<Vec<NetworkPacket>, String> {
        let done = self.done_count();
        if numbers
            .first()
            .is_none_or(|first| *first == 0 || *first > done)
        {
            return Ok(Vec::new());
        }
        let mut index = File::open(self.dir.join("rows.idx")).map_err(|e| e.to_string())?;
        let mut rows =
            BufReader::new(File::open(self.dir.join("rows.tsv")).map_err(|e| e.to_string())?);
        let mut packets = Vec::with_capacity(numbers.len());
        let mut line = Vec::new();
        for &number in numbers {
            if number == 0 || number > done {
                break;
            }
            index
                .seek(SeekFrom::Start((number - 1) * 8))
                .map_err(|e| e.to_string())?;
            let offset = read_u64(&mut index)?;
            rows.seek(SeekFrom::Start(offset))
                .map_err(|e| e.to_string())?;
            line.clear();
            rows.by_ref()
                .take((MAX_RECORD_SIZE + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?;
            if line.len() > MAX_RECORD_SIZE {
                return Err("the stored packet row is damaged".into());
            }
            let packet = decode(std::str::from_utf8(&line).map_err(|_| "damaged packet row")?)?;
            if packet.number != number {
                return Err("the stored packet rows do not match their index".into());
            }
            packets.push(packet);
        }
        Ok(packets)
    }

    /// Size in bytes of the stored rows and index, for the cache check.
    pub(super) fn disk_sizes(dir: &Path) -> Option<(u64, u64)> {
        Some((
            fs::metadata(dir.join("rows.tsv")).ok()?.len(),
            fs::metadata(dir.join("rows.idx")).ok()?.len(),
        ))
    }
}

impl Drop for RowStore {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Appends validated rows and publishes them to readers in batches.
pub(super) struct RowWriter {
    rows: BufWriter<File>,
    index: BufWriter<File>,
    size: u64,
    count: u64,
    unpublished: u64,
}

impl RowWriter {
    /// Continue after the rows already stored (`store.done_count()`).
    pub(super) fn open(store: &RowStore) -> Result<Self, String> {
        let open = |name: &str| {
            OpenOptions::new()
                .append(true)
                .open(store.dir.join(name))
                .map_err(|e| format!("packet rows: {e}"))
        };
        let count = store.done_count();
        let rows = open("rows.tsv")?;
        let size = rows.metadata().map_err(|e| e.to_string())?.len();
        let index = open("rows.idx")?;
        if index.metadata().map_err(|e| e.to_string())?.len() != count * 8 {
            return Err("the stored packet index does not match its rows".into());
        }
        Ok(Self {
            rows: BufWriter::new(rows),
            index: BufWriter::new(index),
            size,
            count,
            unpublished: 0,
        })
    }

    pub(super) fn count(&self) -> u64 {
        self.count
    }

    /// Store `packet`, which must be the next frame.
    pub(super) fn push(&mut self, store: &RowStore, packet: &NetworkPacket) -> Result<(), String> {
        if packet.number != self.count + 1 {
            return Err(format!(
                "TShark printed frame {} where frame {} was expected",
                packet.number,
                self.count + 1
            ));
        }
        let line = encode(packet);
        let size = line.len() as u64 + 1;
        if self.size.saturating_add(size) > MAX_ROWS_SIZE {
            self.publish(store)?;
            return Err("the packet list reached its 1 GiB limit; open the capture in Wireshark for the rest".into());
        }
        self.index
            .write_all(&self.size.to_le_bytes())
            .and_then(|()| self.rows.write_all(line.as_bytes()))
            .and_then(|()| self.rows.write_all(b"\n"))
            .map_err(|e| format!("packet rows write: {e}"))?;
        self.size += size;
        self.count += 1;
        self.unpublished += 1;
        if self.unpublished >= 1000 {
            self.publish(store)?;
        }
        Ok(())
    }

    /// Make every pushed row readable.
    pub(super) fn publish(&mut self, store: &RowStore) -> Result<(), String> {
        self.rows
            .flush()
            .and_then(|()| self.index.flush())
            .map_err(|e| format!("packet rows flush: {e}"))?;
        self.unpublished = 0;
        store.done_count.store(self.count, Ordering::Release);
        Ok(())
    }
}
