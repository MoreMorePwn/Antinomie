//! Checked ANTT application protocol parsing and bounded, disk-backed assembly.
use crate::{
    api::{EventSummary, FieldSummary},
    storage::private_dir,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

#[derive(Default)]
struct Issues(Vec<String>);
impl Issues {
    fn push(&mut self, value: String) {
        if self.0.len() < 32 && !self.0.contains(&value) {
            self.0.push(value);
        }
    }
    fn clone(&self) -> Vec<String> {
        self.0.clone()
    }
}
impl std::ops::Deref for Issues {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}
type Result<T> = std::result::Result<T, ParseError>;
fn error(message: impl Into<String>) -> ParseError {
    ParseError(message.into())
}
pub(crate) fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2)
            .ok_or_else(|| error("truncated u16"))?
            .try_into()
            .map_err(|_| error("u16 size"))?,
    ))
}
pub(crate) fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4)
            .ok_or_else(|| error("truncated u32"))?
            .try_into()
            .map_err(|_| error("u32 size"))?,
    ))
}
pub(crate) fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8)
            .ok_or_else(|| error("truncated u64"))?
            .try_into()
            .map_err(|_| error("u64 size"))?,
    ))
}

#[derive(Clone, Debug)]
pub struct Header {
    pub record_type: u16,
    pub flags: u32,
    pub schema_id: u32,
    pub stream_id: u64,
    pub task_cookie: u64,
    pub call_id: u64,
    pub event_seq: u64,
    pub packet_seq: u64,
    pub timestamp_ns: u64,
    pub tid: u32,
    pub cpu: u32,
    pub syscall_nr: u64,
    pub abi: u16,
    pub phase: u8,
    pub fragment: u8,
    pub object_id: u32,
    pub object_offset: u64,
    pub object_total: u64,
}
pub fn parse_packet(packet: &[u8]) -> Result<(Header, &[u8])> {
    if packet.len() > 262112 {
        return Err(error("packet exceeds application transport limit"));
    }
    if packet.len() < 128 {
        return Err(error("truncated ANTT header"));
    }
    if &packet[..4] != b"ANTT" {
        return Err(error("invalid ANTT magic"));
    }
    if u16_at(packet, 4)? != 1 || u16_at(packet, 6)? != 0 {
        return Err(error("unsupported ANTT version"));
    }
    if u16_at(packet, 8)? != 128
        || u32_at(packet, 12)? as usize != packet.len()
        || u32_at(packet, 120)? as usize != packet.len() - 128
    {
        return Err(error("inconsistent ANTT lengths"));
    }
    if u32_at(packet, 124)? != 0 {
        return Err(error("nonzero ANTT reserved word"));
    }
    let h = Header {
        record_type: u16_at(packet, 10)?,
        flags: u32_at(packet, 16)?,
        schema_id: u32_at(packet, 20)?,
        stream_id: u64_at(packet, 24)?,
        task_cookie: u64_at(packet, 32)?,
        call_id: u64_at(packet, 40)?,
        event_seq: u64_at(packet, 48)?,
        packet_seq: u64_at(packet, 56)?,
        timestamp_ns: u64_at(packet, 64)?,
        tid: u32_at(packet, 76)?,
        cpu: u32_at(packet, 80)?,
        syscall_nr: u64_at(packet, 88)?,
        abi: u16_at(packet, 96)?,
        phase: packet[98],
        fragment: packet[99],
        object_id: u32_at(packet, 100)?,
        object_offset: u64_at(packet, 104)?,
        object_total: u64_at(packet, 112)?,
    };
    let b = &packet[128..];
    match h.record_type {
        1 => {
            if !(1..=3).contains(&h.phase) || !(1..=5).contains(&h.fragment) {
                return Err(error("invalid phase or fragment"));
            }
            if (h.fragment == 1 || h.fragment == 5) && h.object_id != 0 {
                return Err(error("event fragment has object id"));
            }
            if (2..=4).contains(&h.fragment) && h.object_id == 0 {
                return Err(error("field fragment lacks object id"));
            }
            if h.fragment != 3 && h.object_offset != 0 {
                return Err(error("offset on non-data fragment"));
            }
            match h.fragment {
                1 => {
                    if b.len() != 120
                        || u32_at(b, 52)? != 0
                        || u32_at(b, 116)? != 0
                        || !(b[48] <= 6 || b[48] == 255)
                        || b[49] > 4
                    {
                        return Err(error("invalid EVENT_BEGIN"));
                    }
                }
                2 => {
                    if b.len() < 40 {
                        return Err(error("truncated FIELD_BEGIN"));
                    }
                    let key_len = usize::from(u16_at(b, 32)?);
                    let layout_len = usize::from(u16_at(b, 34)?);
                    if key_len > 255
                        || layout_len > 255
                        || b.len() != 40 + key_len + layout_len
                        || u16_at(b, 6)? != 0
                        || !(b[0] < 6 || b[0] == 255)
                        || !(1..=3).contains(&b[1])
                        || !(1..=5).contains(&u16_at(b, 2)?)
                        || !(1..=5).contains(&u16_at(b, 4)?)
                        || !b[40..].is_ascii()
                    {
                        return Err(error("invalid FIELD_BEGIN descriptor"));
                    }
                }
                3 => {
                    let end = h
                        .object_offset
                        .checked_add(b.len() as u64)
                        .ok_or_else(|| error("chunk extent overflow"))?;
                    if h.object_total != u64::MAX && end > h.object_total {
                        return Err(error("chunk exceeds declared object total"));
                    }
                }
                4 | 5 => {
                    if b.len() != 32 {
                        return Err(error("invalid terminal fragment length"));
                    }
                }
                _ => return Err(error("unknown fragment")),
            }
        }
        2 => {
            if b.len() != 96
                || h.task_cookie != 0
                || h.call_id != 0
                || h.event_seq != 0
                || h.syscall_nr != 0
                || h.abi != 0
                || h.phase != 0
                || h.fragment != 0
                || h.object_id != 0
                || h.object_offset != 0
                || h.object_total != 0
                || u32_at(b, 76)? != 0
            {
                return Err(error("invalid recorder health packet"));
            }
        }
        _ => return Err(error("unsupported ANTT record type")),
    }
    Ok((h, b))
}

type Key = (u64, u64, u64, u8, u64);
struct Field {
    summary: FieldSummary,
    begin: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
    chunks: BTreeMap<u64, (u64, PathBuf)>,
    chunk_count: u64,
    issues: Issues,
    total: Option<u64>,
}
impl Field {
    fn new(id: u32) -> Self {
        Self {
            summary: FieldSummary {
                object_id: id,
                key: format!("object {id}"),
                layout: String::new(),
                logical_len: None,
                captured_len: 0,
                status: None,
                capture_error: 0,
                complete: false,
                preview: Vec::new(),
                raw_path: None,
                ranges: Vec::new(),
            },
            begin: None,
            end: None,
            chunks: BTreeMap::new(),
            chunk_count: 0,
            issues: Issues::default(),
            total: None,
        }
    }
    fn summary(&self) -> FieldSummary {
        let mut s = self.summary.clone();
        s.ranges = self.chunks.iter().map(|(o, (len, _))| (*o, *len)).collect();
        let mut offset = 0;
        let contiguous = self.chunks.iter().all(|(o, (len, _))| {
            let matches = *o == offset;
            offset = offset.saturating_add(*len);
            matches
        });
        let end = self.end.as_deref();
        let attempted = end.and_then(|b| u64_at(b, 24).ok());
        s.complete = self.begin.is_some()
            && end.is_some()
            && s.status == Some(0)
            && s.logical_len == Some(offset)
            && s.captured_len == offset
            && contiguous
            && attempted == Some(self.chunk_count)
            && self.issues.is_empty();
        s
    }
}
struct Event {
    summary: EventSummary,
    begin: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
    fields: BTreeMap<u32, Field>,
    packets: BTreeMap<u64, [u8; 32]>,
    issues: Issues,
}
impl Event {
    fn new(h: &Header) -> Self {
        Self {
            summary: EventSummary {
                stream_id: h.stream_id,
                task_cookie: h.task_cookie,
                call_id: h.call_id,
                event_seq: h.event_seq,
                phase: h.phase,
                syscall_nr: h.syscall_nr,
                syscall_name: syscall_name(h.syscall_nr).into(),
                tid: h.tid,
                cpu: h.cpu,
                timestamp_ns: h.timestamp_ns,
                args: None,
                result: None,
                complete: false,
                issues: Vec::new(),
                fields: Vec::new(),
            },
            begin: None,
            end: None,
            fields: BTreeMap::new(),
            packets: BTreeMap::new(),
            issues: Issues::default(),
        }
    }
    fn summary(&self) -> EventSummary {
        let mut s = self.summary.clone();
        s.issues = self.issues.clone();
        s.fields = self.fields.values().map(Field::summary).collect();
        if self.begin.is_none() {
            s.issues.push("missing EVENT_BEGIN".into());
        }
        if self.end.is_none() {
            s.issues.push("missing EVENT_END".into());
        }
        for field in self.fields.values() {
            if field.begin.is_none() {
                s.issues.push(format!(
                    "object {} missing FIELD_BEGIN",
                    field.summary.object_id
                ));
            }
            if field.end.is_none() {
                s.issues.push(format!(
                    "object {} missing FIELD_END",
                    field.summary.object_id
                ));
            }
            if !field.summary().complete {
                s.issues.push(format!(
                    "object {} capture incomplete, status {:?}",
                    field.summary.object_id, field.summary.status
                ));
            }
            s.issues.extend(field.issues.iter().cloned());
        }
        if let Some(end) = &self.end {
            let objects = u64_at(end, 0).unwrap_or(u64::MAX);
            let attempted = u64_at(end, 8).unwrap_or(u64::MAX);
            if objects != self.fields.len() as u64 {
                s.issues.push("missing or inconsistent object count".into());
            }
            if attempted != self.packets.len() as u64 {
                s.issues
                    .push("packet loss or inconsistent event packet count".into());
            }
            if let (Some((first, _)), Some((last, _))) = (
                self.packets.first_key_value(),
                self.packets.last_key_value(),
            ) && last.saturating_sub(*first).saturating_add(1) != self.packets.len() as u64
            {
                s.issues.push("packet sequence gap".into());
            }
            if u64_at(end, 16).unwrap_or(1) != 0 || u64_at(end, 24).unwrap_or(1) != 0 {
                s.issues
                    .push("recorder reports event loss or capture failure".into());
            }
        }
        s.complete = s.issues.is_empty();
        s
    }
}

pub struct Assembler {
    directory: PathBuf,
    quota: u64,
    stored_len: u64,
    events: BTreeMap<Key, Event>,
    order: VecDeque<Key>,
    pub evicted_count: u64,
    pub malformed_count: u64,
    enabled: bool,
    packet_count: usize,
    field_count: usize,
    chunk_count: usize,
    evicted: VecDeque<EventSummary>,
}
impl Assembler {
    pub fn new(directory: PathBuf, quota: u64) -> Result<Self> {
        private_dir(&directory).map_err(|e| error(e.to_string()))?;
        Ok(Self {
            directory,
            quota,
            stored_len: 0,
            events: BTreeMap::new(),
            order: VecDeque::new(),
            evicted_count: 0,
            malformed_count: 0,
            enabled: true,
            packet_count: 0,
            field_count: 0,
            chunk_count: 0,
            evicted: VecDeque::new(),
        })
    }
    pub fn stop_saving(&mut self) {
        self.enabled = false;
    }
    pub fn stored_len(&self) -> u64 {
        self.stored_len
    }
    pub fn set_storage_limit(&mut self, quota: u64) {
        self.quota = quota;
    }
    fn evict_oldest(&mut self) {
        if let Some(old) = self.order.pop_front()
            && let Some(event) = self.events.remove(&old)
        {
            self.packet_count = self.packet_count.saturating_sub(event.packets.len());
            self.field_count = self.field_count.saturating_sub(event.fields.len());
            self.chunk_count = self
                .chunk_count
                .saturating_sub(event.fields.values().map(|f| f.chunks.len()).sum());
            let mut summary = event.summary();
            summary.complete = false;
            summary
                .issues
                .push("host retention eviction; raw archive remains available".into());
            if self.evicted.len() >= 64 {
                self.evicted.pop_front();
            }
            self.evicted.push_back(summary);
            self.evicted_count += 1;
        }
    }
    pub fn ingest(&mut self, packet: &[u8]) -> Result<Option<EventSummary>> {
        let (h, b) = match parse_packet(packet) {
            Ok(v) => v,
            Err(e) => {
                self.malformed_count += 1;
                return Err(e);
            }
        };
        if h.record_type == 2 {
            return Ok(None);
        }
        let key = (h.stream_id, h.task_cookie, h.call_id, h.phase, h.event_seq);
        while !self.order.is_empty()
            && (self.packet_count >= 65536 || self.field_count >= 4096 || self.chunk_count >= 16384)
        {
            self.evict_oldest();
        }
        if !self.events.contains_key(&key) {
            if self.events.len() >= 2048 {
                self.evict_oldest();
            }
            self.events.insert(key, Event::new(&h));
            self.order.push_back(key);
        }
        let e = self
            .events
            .get_mut(&key)
            .ok_or_else(|| error("missing event state"))?;
        if e.packets.len() >= 8192 && !e.packets.contains_key(&h.packet_seq) {
            return Err(error("event packet state limit"));
        }
        let fingerprint: [u8; 32] = Sha256::digest(packet).into();
        let duplicate = if let Some(previous) = e.packets.get(&h.packet_seq) {
            if previous != &fingerprint {
                e.issues
                    .push("packet sequence reused with conflicting content".into());
            }
            true
        } else {
            e.packets.insert(h.packet_seq, fingerprint);
            false
        };
        if !duplicate {
            self.packet_count += 1;
        }
        if e.summary.syscall_nr != h.syscall_nr {
            e.issues.push("conflicting syscall identity".into());
        }
        if h.flags & !0x1f != 0 {
            e.issues
                .push(format!("unknown header flags 0x{:x}", h.flags));
        }
        if h.flags & 7 != 0 {
            e.issues
                .push("recorder header reports incomplete capture".into());
        }
        if h.schema_id != 1 || h.abi != 1 {
            e.issues.push("unknown schema or ABI; raw only".into());
        }
        match h.fragment {
            1 => {
                if let Some(previous) = &e.begin {
                    if previous != b {
                        e.issues.push("conflicting EVENT_BEGIN".into());
                    }
                } else {
                    let mut args = [0; 6];
                    for (i, a) in args.iter_mut().enumerate() {
                        *a = u64_at(b, i * 8)?;
                    }
                    e.summary.args = Some(args);
                    if b[49] != 0 {
                        e.summary.result = Some(u64_at(b, 56)? as i64);
                    }
                    e.begin = Some(b.to_vec());
                }
            }
            5 => {
                if let Some(previous) = &e.end {
                    if previous != b {
                        e.issues.push("conflicting EVENT_END".into());
                    }
                } else {
                    e.end = Some(b.to_vec());
                }
            }
            2..=4 => {
                if e.fields.len() >= 256 && !e.fields.contains_key(&h.object_id) {
                    return Err(error("event object state limit"));
                }
                if !e.fields.contains_key(&h.object_id) {
                    self.field_count += 1;
                }
                let f = e
                    .fields
                    .entry(h.object_id)
                    .or_insert_with(|| Field::new(h.object_id));
                if h.object_total != u64::MAX {
                    if f.total.is_some_and(|total| total != h.object_total) {
                        f.issues.push("inconsistent object total".into());
                    } else {
                        f.total = Some(h.object_total);
                    }
                }
                match h.fragment {
                    2 => {
                        if let Some(previous) = &f.begin {
                            if previous != b {
                                f.issues.push("conflicting FIELD_BEGIN".into());
                            }
                        } else {
                            let n = usize::from(u16_at(b, 32)?);
                            f.summary.key = String::from_utf8_lossy(&b[40..40 + n]).into_owned();
                            f.summary.layout = String::from_utf8_lossy(&b[40 + n..]).into_owned();
                            f.begin = Some(b.to_vec());
                        }
                    }
                    4 => {
                        if let Some(previous) = &f.end {
                            if previous != b {
                                f.issues.push("conflicting FIELD_END".into());
                            }
                        } else {
                            let logical = u64_at(b, 0)?;
                            f.summary.logical_len = (logical != u64::MAX).then_some(logical);
                            f.summary.captured_len = u64_at(b, 8)?;
                            f.summary.status = Some(u32_at(b, 16)?);
                            f.summary.capture_error = u32_at(b, 20)? as i32;
                            f.end = Some(b.to_vec());
                            if f.total.is_some_and(|n| n != logical) {
                                f.issues
                                    .push("terminal length disagrees with object total".into());
                            }
                        }
                    }
                    3 => {
                        let chunk_end = h
                            .object_offset
                            .checked_add(b.len() as u64)
                            .ok_or_else(|| error("chunk overflow"))?;
                        if f.summary.logical_len.is_some_and(|total| chunk_end > total) {
                            f.issues.push("chunk exceeds final semantic extent".into());
                            return Ok(Some(e.summary()));
                        }
                        if let Some((&offset, (len, path))) =
                            f.chunks.range(..chunk_end).next_back()
                            && offset.saturating_add(*len) > h.object_offset
                        {
                            if offset == h.object_offset && *len == b.len() as u64 {
                                let mut previous = vec![0; b.len()];
                                File::open(path)
                                    .and_then(|mut file| {
                                        file.seek(SeekFrom::Start(offset))
                                            .and_then(|_| file.read_exact(&mut previous))
                                    })
                                    .map_err(|e| error(e.to_string()))?;
                                if previous != b {
                                    f.issues.push("conflicting duplicate chunk".into());
                                }
                            } else {
                                f.issues.push("overlapping chunks".into());
                            }
                            return Ok(Some(e.summary()));
                        }
                        if duplicate {
                            f.issues
                                .push("reused packet sequence with different payload".into());
                        }
                        if f.chunks.len() >= 4096 {
                            f.issues.push("host chunk state limit".into());
                            return Ok(Some(e.summary()));
                        }
                        if !self.enabled
                            || chunk_end > self.quota
                            || self.stored_len.saturating_add(b.len() as u64) > self.quota
                        {
                            f.issues
                                .push("host object storage unavailable or quota exhausted".into());
                            return Ok(Some(e.summary()));
                        }
                        let path = self.directory.join(format!(
                            "{}-{}-{}-{}-{}-{}.raw",
                            h.stream_id,
                            h.task_cookie,
                            h.call_id,
                            h.phase,
                            h.event_seq,
                            h.object_id
                        ));
                        let result = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create(true)
                            .truncate(false)
                            .mode(0o600)
                            .open(&path)
                            .and_then(|mut file| {
                                file.seek(SeekFrom::Start(h.object_offset))
                                    .and_then(|_| file.write_all(b))
                            });
                        if let Err(err) = result {
                            f.issues.push(format!("host object persistence: {err}"));
                            return Ok(Some(e.summary()));
                        }
                        self.stored_len += b.len() as u64;
                        self.chunk_count += 1;
                        f.chunk_count += 1;
                        f.chunks
                            .insert(h.object_offset, (b.len() as u64, path.clone()));
                        f.summary.raw_path = Some(path);
                        if h.object_offset == 0 {
                            f.summary.preview = b[..b.len().min(256)].to_vec();
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(Some(e.summary()))
    }
    pub fn history(&self) -> Vec<EventSummary> {
        self.evicted
            .iter()
            .cloned()
            .chain(
                self.order
                    .iter()
                    .filter_map(|k| self.events.get(k).map(Event::summary)),
            )
            .collect()
    }
}

pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        16 => "ioctl",
        19 => "readv",
        20 => "writev",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        62 => "kill",
        82 => "rename",
        87 => "unlink",
        231 => "exit_group",
        257 => "openat",
        322 => "execveat",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(kind: u8, id: u32, offset: u64, body: &[u8], seq: u64) -> Vec<u8> {
        let mut p = vec![0; 128];
        p[..4].copy_from_slice(b"ANTT");
        p[4..6].copy_from_slice(&1u16.to_le_bytes());
        p[8..10].copy_from_slice(&128u16.to_le_bytes());
        p[10..12].copy_from_slice(&1u16.to_le_bytes());
        p[12..16].copy_from_slice(&(128u32 + body.len() as u32).to_le_bytes());
        p[20..24].copy_from_slice(&1u32.to_le_bytes());
        p[56..64].copy_from_slice(&seq.to_le_bytes());
        p[96..98].copy_from_slice(&1u16.to_le_bytes());
        p[98] = 1;
        p[99] = kind;
        p[100..104].copy_from_slice(&id.to_le_bytes());
        p[104..112].copy_from_slice(&offset.to_le_bytes());
        p[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
        p[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
        p.extend(body);
        p
    }
    #[test]
    fn rejects_all_truncated_headers_and_checked_overflow() {
        let p = packet(3, 1, u64::MAX, b"x", 1);
        assert!(parse_packet(&p).is_err());
        for len in 0..128 {
            assert!(parse_packet(&p[..len]).is_err());
        }
    }
    #[test]
    fn reassembles_reordered_fragments_without_claiming_gaps_complete() {
        let path = std::env::temp_dir().join(format!("ant-parser-{}", crate::storage::unique_id()));
        let mut a = Assembler::new(path.clone(), 1024).unwrap();
        let mut end = [0; 32];
        end[..8].copy_from_slice(&1u64.to_le_bytes());
        end[8..16].copy_from_slice(&5u64.to_le_bytes());
        assert!(
            !a.ingest(&packet(5, 0, 0, &end, 5))
                .unwrap()
                .unwrap()
                .complete
        );
        let mut field = [0; 40];
        field[0] = 1;
        field[1] = 1;
        field[2] = 1;
        field[4] = 1;
        a.ingest(&packet(2, 1, 0, &field, 2)).unwrap();
        a.ingest(&packet(3, 1, 0, b"abc", 3)).unwrap();
        let mut terminal = [0; 32];
        terminal[..8].copy_from_slice(&3u64.to_le_bytes());
        terminal[8..16].copy_from_slice(&3u64.to_le_bytes());
        terminal[24..32].copy_from_slice(&1u64.to_le_bytes());
        a.ingest(&packet(4, 1, 0, &terminal, 4)).unwrap();
        let event = a.ingest(&packet(1, 0, 0, &[0; 120], 1)).unwrap().unwrap();
        assert!(event.complete);
        assert_eq!(event.fields[0].preview, b"abc");
        a.ingest(&packet(3, 1, 0, b"xyz", 3)).unwrap();
        assert!(!a.history()[0].complete);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn copy_fault_is_never_complete() {
        let path = std::env::temp_dir().join(format!("ant-fault-{}", crate::storage::unique_id()));
        let mut a = Assembler::new(path.clone(), 32).unwrap();
        let mut terminal = [0; 32];
        terminal[16] = 1;
        let s = a.ingest(&packet(4, 1, 0, &terminal, 1)).unwrap().unwrap();
        assert!(!s.complete);
        assert_eq!(s.fields[0].status, Some(1));
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn streams_ten_mebibytes_and_keeps_only_bounded_previews() {
        let path = std::env::temp_dir().join(format!("ant-large-{}", crate::storage::unique_id()));
        let mut a = Assembler::new(path.clone(), 12 * 1024 * 1024).unwrap();
        a.ingest(&packet(1, 0, 0, &[0; 120], 1)).unwrap();
        let mut field = [0; 40];
        field[0] = 1;
        field[1] = 1;
        field[2] = 1;
        field[4] = 1;
        a.ingest(&packet(2, 1, 0, &field, 2)).unwrap();
        let mut chunk = vec![0; 65536];
        for n in 0..160u64 {
            chunk.fill(n as u8);
            a.ingest(&packet(3, 1, n * 65536, &chunk, n + 3)).unwrap();
        }
        let mut end = [0; 32];
        end[..8].copy_from_slice(&(10u64 * 1024 * 1024).to_le_bytes());
        end[8..16].copy_from_slice(&(10u64 * 1024 * 1024).to_le_bytes());
        end[24..32].copy_from_slice(&160u64.to_le_bytes());
        a.ingest(&packet(4, 1, 0, &end, 163)).unwrap();
        let mut event_end = [0; 32];
        event_end[..8].copy_from_slice(&1u64.to_le_bytes());
        event_end[8..16].copy_from_slice(&164u64.to_le_bytes());
        let event = a
            .ingest(&packet(5, 0, 0, &event_end, 164))
            .unwrap()
            .unwrap();
        assert!(event.complete);
        assert_eq!(event.fields[0].preview.len(), 256);
        assert_eq!(event.fields[0].ranges.len(), 160);
        let mut file = File::open(event.fields[0].raw_path.as_ref().unwrap()).unwrap();
        file.seek(SeekFrom::Start(159 * 65536)).unwrap();
        let mut sample = [0; 32];
        file.read_exact(&mut sample).unwrap();
        assert_eq!(sample, [159; 32]);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn malformed_field_length_mutations_cannot_panic() {
        let mut field = [0; 40];
        field[0] = 1;
        field[1] = 1;
        field[2] = 1;
        field[4] = 1;
        let original = packet(2, 1, 0, &field, 1);
        for index in 0..original.len() {
            for value in [0, 1, 127, 255] {
                let mut p = original.clone();
                p[index] = value;
                let _ = parse_packet(&p);
            }
        }
    }
}
