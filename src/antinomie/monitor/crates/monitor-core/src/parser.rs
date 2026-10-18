//! Checked ANTT application protocol parsing and bounded, disk-backed assembly.
use crate::{
    api::{EventSummary, FieldSummary},
    object_pack::{FieldKey, PackWriter},
    storage::private_dir,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
};

mod objects;
use objects::StoreError;

/// Default aggregate field budget. Large events share this same bounded pool
/// with other events instead of having a smaller, conflicting per-event cap.
pub(crate) const MAX_RETAINED_FIELDS: usize = 4096;

#[cfg(test)]
mod field_tests;

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
    pub root_task_cookie: u64,
    pub capture_cookie: u64,
    pub record_type: u16,
    pub flags: u32,
    pub schema_id: u32,
    pub stream_id: u64,
    pub task_cookie: u64,
    pub call_id: u64,
    pub event_seq: u64,
    pub packet_seq: u64,
    pub timestamp_ns: u64,
    /// Thread group (process) ID.
    pub pid: u32,
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
    let minor = u16_at(packet, 6)?;
    if u16_at(packet, 4)? != 1 || minor > 2 {
        return Err(error("unsupported ANTT version"));
    }
    let header_size = match minor {
        0 => 128,
        1 => 136,
        _ => 144,
    };
    if packet.len() < header_size {
        return Err(error("truncated ANTT extended header"));
    }
    if usize::from(u16_at(packet, 8)?) != header_size
        || u32_at(packet, 12)? as usize != packet.len()
        || u32_at(packet, 120)? as usize != packet.len() - header_size
    {
        return Err(error("inconsistent ANTT lengths"));
    }
    if u32_at(packet, 124)? != 0 {
        return Err(error("nonzero ANTT reserved word"));
    }
    let h = Header {
        root_task_cookie: if minor >= 1 { u64_at(packet, 128)? } else { 0 },
        capture_cookie: if minor == 2 { u64_at(packet, 136)? } else { 0 },
        record_type: u16_at(packet, 10)?,
        flags: u32_at(packet, 16)?,
        schema_id: u32_at(packet, 20)?,
        stream_id: u64_at(packet, 24)?,
        task_cookie: u64_at(packet, 32)?,
        call_id: u64_at(packet, 40)?,
        event_seq: u64_at(packet, 48)?,
        packet_seq: u64_at(packet, 56)?,
        timestamp_ns: u64_at(packet, 64)?,
        pid: u32_at(packet, 72)?,
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
    let b = &packet[header_size..];
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
    /// Chunks by offset in the object: length and location in the object store.
    chunks: BTreeMap<u64, (u64, [u8; 16])>,
    /// The field's number in the object index, once its first chunk is stored.
    number: Option<u32>,
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
            number: None,
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
/// Packet sequence numbers an event received, kept as contiguous ranges so a
/// call of any size fits, plus fingerprints of its first packets to tell a
/// repeated packet from a conflicting one.
#[derive(Default)]
struct PacketSet {
    /// Start → end (inclusive) of each received run of sequence numbers.
    ranges: BTreeMap<u64, u64>,
    count: u64,
    fingerprints: std::collections::HashMap<u64, [u8; 32]>,
}
/// Packets per event whose fingerprints are kept.
const FINGERPRINTED: usize = 8192;
impl PacketSet {
    fn len(&self) -> u64 {
        self.count
    }
    fn first(&self) -> Option<u64> {
        self.ranges.first_key_value().map(|(start, _)| *start)
    }
    fn last(&self) -> Option<u64> {
        self.ranges.last_key_value().map(|(_, end)| *end)
    }
    fn contains(&self, seq: u64) -> bool {
        self.ranges
            .range(..=seq)
            .next_back()
            .is_some_and(|(_, end)| seq <= *end)
    }
    /// Record a packet; returns (already received, with different content).
    fn insert(&mut self, seq: u64, packet: &[u8]) -> (bool, bool) {
        if self.contains(seq) {
            let conflicting = self
                .fingerprints
                .get(&seq)
                .is_some_and(|previous| *previous != <[u8; 32]>::from(Sha256::digest(packet)));
            return (true, conflicting);
        }
        if self.fingerprints.len() < FINGERPRINTED {
            self.fingerprints.insert(seq, Sha256::digest(packet).into());
        }
        self.count += 1;
        let joins_before = seq.checked_sub(1).and_then(|previous| {
            self.ranges
                .range(..=previous)
                .next_back()
                .filter(|(_, end)| **end == previous)
                .map(|(start, _)| *start)
        });
        let joins_after = seq
            .checked_add(1)
            .and_then(|next| self.ranges.remove(&next));
        let start = joins_before.unwrap_or(seq);
        self.ranges.insert(start, joins_after.unwrap_or(seq));
        (false, false)
    }
}

struct Event {
    summary: EventSummary,
    capture_cookie: u64,
    begin: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
    fields: BTreeMap<u32, Field>,
    packets: PacketSet,
    issues: Issues,
    /// Queued for retirement: its END and every field's end have arrived.
    finished: bool,
}
impl Event {
    fn new(h: &Header) -> Self {
        Self {
            summary: EventSummary {
                root_task_cookie: h.root_task_cookie,
                stream_id: h.stream_id,
                task_cookie: h.task_cookie,
                call_id: h.call_id,
                event_seq: h.event_seq,
                phase: h.phase,
                syscall_nr: h.syscall_nr,
                syscall_name: crate::syscalls::name(h.syscall_nr),
                pid: h.pid,
                tid: h.tid,
                cpu: h.cpu,
                timestamp_ns: h.timestamp_ns,
                args: None,
                result: None,
                complete: false,
                issues: Vec::new(),
                fields: Vec::new(),
            },
            capture_cookie: h.capture_cookie,
            begin: None,
            end: None,
            fields: BTreeMap::new(),
            packets: PacketSet::default(),
            issues: Issues::default(),
            finished: false,
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
                    "object {} capture incomplete, status {}",
                    field.summary.object_id,
                    field.summary.status.map_or("missing", status_name)
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
            if attempted != self.packets.len() {
                s.issues
                    .push("packet loss or inconsistent event packet count".into());
            }
            if let (Some(first), Some(last)) = (self.packets.first(), self.packets.last())
                && last.saturating_sub(first).saturating_add(1) != self.packets.len()
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
    read_only: bool,
    saving_error: Option<String>,
    packet_count: usize,
    field_count: usize,
    chunk_count: usize,
    evicted: VecDeque<EventSummary>,
    /// Finished events, oldest first: they leave the table before unfinished ones.
    finished: VecDeque<Key>,
    /// Events the table holds before it retires or evicts one.
    capacity: usize,
    /// The recording writer thread's first object write error.
    write_error: crate::writer::ErrorSlot,
    /// Where chunks are stored; none for a reader of a saved archive.
    pack: Option<PackWriter>,
}
impl Assembler {
    pub fn new(directory: PathBuf, quota: u64) -> Result<Self> {
        private_dir(&directory).map_err(|e| error(e.to_string()))?;
        Ok(Self::empty(directory, quota, false))
    }
    fn empty(directory: PathBuf, quota: u64, read_only: bool) -> Self {
        let write_error = crate::writer::error_slot();
        Self {
            pack: (!read_only).then(|| PackWriter::new(directory.clone(), write_error.clone())),
            directory,
            quota,
            stored_len: 0,
            events: BTreeMap::new(),
            order: VecDeque::new(),
            evicted_count: 0,
            malformed_count: 0,
            enabled: true,
            read_only,
            saving_error: None,
            packet_count: 0,
            field_count: 0,
            chunk_count: 0,
            evicted: VecDeque::new(),
            finished: VecDeque::new(),
            capacity: MAX_RETAINED_FIELDS / 2,
            write_error,
        }
    }
    /// A stand-in for an assembler whose recording moved to a flush job.
    pub(crate) fn sealed() -> Self {
        Self::empty(PathBuf::new(), 0, true)
    }
    /// Hand the chunks stored since the last call to the recording writer.
    pub fn flush(&mut self) {
        if let Some(pack) = &mut self.pack
            && let Err(error) = pack.flush()
        {
            self.saving_error
                .get_or_insert_with(|| format!("host object persistence: {error}"));
            self.enabled = false;
        }
    }
    /// Wait until every chunk stored so far is written, and make the object
    /// files durable. Reports the first failure of this assembler's writes.
    pub(crate) fn sync(&mut self) -> std::result::Result<(), String> {
        match &mut self.pack {
            Some(pack) => pack.sync(),
            None => Ok(()),
        }
    }
    pub fn stop_saving(&mut self) {
        self.enabled = false;
    }
    /// The first saving failure, including object writes the recording
    /// writer thread has failed since the last packet.
    pub(crate) fn saving_error(&mut self) -> Option<&str> {
        if self.saving_error.is_none()
            && !self.read_only
            && let Some(error) = crate::writer::error_of(&self.write_error)
        {
            self.saving_error = Some(error);
            self.enabled = false;
        }
        self.saving_error.as_deref()
    }
    pub(crate) fn open_archive(directory: PathBuf) -> Result<Self> {
        if directory.exists() {
            let root = std::fs::canonicalize(
                directory
                    .parent()
                    .ok_or_else(|| error("archive objects have no parent"))?,
            )
            .map_err(|e| error(e.to_string()))?;
            let objects = std::fs::canonicalize(&directory).map_err(|e| error(e.to_string()))?;
            if !objects.starts_with(root) {
                return Err(error("objects directory escapes recording"));
            }
        }
        Ok(Self::empty(directory, u64::MAX, true))
    }
    /// A reader for an objects directory that [`Self::open_archive`] already
    /// accepted: one check per scan, not one per invocation.
    pub(crate) fn archive_checked(directory: PathBuf) -> Self {
        Self::empty(directory, u64::MAX, true)
    }
    pub fn stored_len(&self) -> u64 {
        self.stored_len
    }
    pub fn set_storage_limit(&mut self, quota: u64) {
        self.quota = quota;
    }
    /// Size the table of events still being assembled (VM transport settings).
    /// Packet, field and chunk limits scale with it in the original ratios.
    pub fn set_event_table(&mut self, events: usize) {
        self.capacity = events.max(64);
    }
    fn over_limits(&self) -> bool {
        self.packet_count >= self.capacity * 32
            || self.field_count >= self.capacity * 2
            || self.chunk_count >= self.capacity * 8
    }
    /// Make room: retire the oldest finished event, which loses nothing but
    /// its place in the live list; only without one evict an unfinished event.
    fn evict_oldest(&mut self) {
        while let Some(key) = self.finished.pop_front() {
            if let Some(event) = self.events.remove(&key) {
                self.forget(&event);
                if self.evicted.len() >= 64 {
                    self.evicted.pop_front();
                }
                self.evicted.push_back(event.summary());
                if self.order.len() > self.capacity * 4 {
                    let events = &self.events;
                    self.order.retain(|key| events.contains_key(key));
                }
                return;
            }
        }
        while let Some(old) = self.order.pop_front() {
            let Some(event) = self.events.remove(&old) else {
                continue;
            };
            self.forget(&event);
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
            return;
        }
    }
    fn forget(&mut self, event: &Event) {
        self.packet_count = self
            .packet_count
            .saturating_sub(event.packets.fingerprints.len());
        self.field_count = self.field_count.saturating_sub(event.fields.len());
        self.chunk_count = self
            .chunk_count
            .saturating_sub(event.fields.values().map(|f| f.chunks.len()).sum());
    }
    pub fn ingest(&mut self, packet: &[u8]) -> Result<Option<EventSummary>> {
        let result = self.ingest_packet(packet);
        if let Ok((h, _)) = parse_packet(packet) {
            let key = (h.stream_id, h.task_cookie, h.call_id, h.phase, h.event_seq);
            if let Some(event) = self.events.get_mut(&key)
                && !event.finished
                && event.end.is_some()
                && event.fields.values().all(|field| field.end.is_some())
            {
                event.finished = true;
                self.finished.push_back(key);
            }
        }
        result
    }
    fn ingest_packet(&mut self, packet: &[u8]) -> Result<Option<EventSummary>> {
        if self.enabled
            && !self.read_only
            && let Some(error) = crate::writer::error_of(&self.write_error)
        {
            self.saving_error.get_or_insert(error);
            self.enabled = false;
        }
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
        while !self.events.is_empty() && self.over_limits() {
            self.evict_oldest();
        }
        if !self.events.contains_key(&key) {
            if self.events.len() >= self.capacity {
                self.evict_oldest();
            }
            self.events.insert(key, Event::new(&h));
            self.order.push_back(key);
        }
        let e = self
            .events
            .get_mut(&key)
            .ok_or_else(|| error("missing event state"))?;
        let fingerprinted = e.packets.fingerprints.len();
        let (duplicate, conflicting) = e.packets.insert(h.packet_seq, packet);
        if conflicting {
            e.issues
                .push("packet sequence reused with conflicting content".into());
        }
        if !duplicate && e.packets.fingerprints.len() > fingerprinted {
            self.packet_count += 1;
        }
        if e.summary.syscall_nr != h.syscall_nr {
            e.issues.push("conflicting syscall identity".into());
        }
        if e.summary.root_task_cookie != h.root_task_cookie {
            e.issues.push("conflicting root task identity".into());
        }
        if e.capture_cookie != h.capture_cookie {
            e.issues
                .push("conflicting observer capture identity".into());
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
                        let field_key = FieldKey {
                            stream: h.stream_id,
                            task: h.task_cookie,
                            call: h.call_id,
                            phase: h.phase,
                            seq: h.event_seq,
                            object: h.object_id,
                        };
                        let fingerprint = crate::object_pack::chunk_fingerprint(b);
                        if let Some((&offset, &(len, prior_fingerprint))) =
                            f.chunks.range(..chunk_end).next_back()
                            && offset.saturating_add(len) > h.object_offset
                        {
                            if offset == h.object_offset && len == b.len() as u64 {
                                // Keep a bounded fingerprint with the chunk so
                                // recognizing a duplicate never waits for an
                                // object writer flush and a disk read.
                                if prior_fingerprint != fingerprint {
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
                        if !self.enabled {
                            f.issues.push("host object saving stopped".into());
                            return Ok(Some(e.summary()));
                        }
                        let stored = objects::store(
                            &mut self.pack,
                            &self.directory,
                            &field_key,
                            &mut f.number,
                            h.object_offset,
                            b,
                            self.quota.saturating_sub(self.stored_len),
                        );
                        let added = match stored {
                            Ok(stored) => stored,
                            Err(failure) => {
                                let message = match failure {
                                    StoreError::Quota => {
                                        "host object quota exhausted; saving stopped".to_string()
                                    }
                                    StoreError::Failed(err) => {
                                        format!("host object persistence: {err}")
                                    }
                                };
                                if !self.read_only {
                                    self.saving_error.get_or_insert(message.clone());
                                    self.enabled = false;
                                }
                                f.issues.push(message);
                                return Ok(Some(e.summary()));
                            }
                        };
                        self.stored_len += added;
                        self.chunk_count += 1;
                        f.chunk_count += 1;
                        f.chunks
                            .insert(h.object_offset, (b.len() as u64, fingerprint));
                        f.summary.raw_path = Some(self.directory.join(field_key.file_name()));
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
    /// The newest `limit` events (table and recently retired), oldest first,
    /// without summarizing the whole table.
    /// Forget the in-memory event table. Everything stays in the archive on
    /// disk; a run whose recording is complete is read from there.
    pub fn release_tables(&mut self) {
        self.events = BTreeMap::new();
        self.order = VecDeque::new();
        self.evicted = VecDeque::new();
        self.finished = VecDeque::new();
    }
    /// Whether the in-memory event table holds anything.
    pub fn holds_tables(&self) -> bool {
        !self.events.is_empty() || !self.evicted.is_empty() || !self.order.is_empty()
    }
    pub fn recent(&self, limit: usize) -> Vec<EventSummary> {
        let mut seen = std::collections::HashSet::new();
        let mut newest: Vec<EventSummary> = self
            .order
            .iter()
            .rev()
            .filter(|key| seen.insert(**key))
            .filter_map(|key| self.events.get(key).map(Event::summary))
            .take(limit)
            .collect();
        let room = limit - newest.len();
        newest.extend(self.evicted.iter().rev().take(room).cloned());
        newest.reverse();
        newest
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
    crate::syscalls::syscall(nr).map_or("unknown", |entry| entry.name.as_str())
}

/// Field capture status names (contract revision 8; `capture_api.h` order).
pub fn status_name(status: u32) -> &'static str {
    const NAMES: [&str; 13] = [
        "COMPLETE",
        "COPY_FAULT",
        "INVALID_EXTENT",
        "UNKNOWN_EXTENT",
        "NO_DECODER",
        "NULL_POINTER",
        "ADDRESS_ONLY",
        "ASYNC_UNOBSERVED",
        "RESOURCE_EXHAUSTED",
        "ABORTED_ON_LOSS",
        "CONTEXT_MISSING",
        "NOT_WRITTEN",
        "NOT_RESIDENT",
    ];
    NAMES.get(status as usize).copied().unwrap_or("UNKNOWN")
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn packet(kind: u8, id: u32, offset: u64, body: &[u8], seq: u64) -> Vec<u8> {
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
    fn releasing_tables_forgets_live_events_and_keeps_saved_counts() {
        let path = std::env::temp_dir().join(format!(
            "ant-release-tables-{}",
            crate::storage::unique_id()
        ));
        let mut assembler = Assembler::new(path.clone(), 1024 * 1024).unwrap();
        for seq in 1..=8 {
            assembler.ingest(&packet(1, 0, 0, &[0; 120], seq)).unwrap();
        }
        assert!(assembler.holds_tables());
        assert!(!assembler.recent(64).is_empty());
        let stored = assembler.stored_len();
        assembler.release_tables();
        assert!(!assembler.holds_tables());
        assert!(assembler.recent(64).is_empty());
        assert_eq!(assembler.stored_len(), stored);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn an_empty_data_fragment_does_not_disable_later_object_saving() {
        let path = std::env::temp_dir().join(format!(
            "ant-empty-fragment-{}",
            crate::storage::unique_id()
        ));
        let mut assembler = Assembler::new(path.clone(), 1024).unwrap();
        assembler.ingest(&packet(3, 1, 0, b"", 1)).unwrap();
        assert!(assembler.saving_error().is_none());
        assembler
            .ingest(&packet(3, 2, 0, b"later field", 2))
            .unwrap();
        assert!(assembler.saving_error().is_none());
        assembler.pack.as_mut().unwrap().sync().unwrap();
        let empty = FieldKey {
            stream: 0,
            task: 0,
            call: 0,
            phase: 1,
            seq: 0,
            object: 1,
        };
        let later = FieldKey { object: 2, ..empty };
        assert_eq!(
            crate::object_pack::read_field_range(&path, &empty, 0, 0).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            crate::object_pack::read_field_range(&path, &later, 0, 11)
                .unwrap()
                .unwrap(),
            b"later field"
        );
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn extended_headers_keep_inherited_root_and_legacy_root_unknown() {
        let legacy = packet(1, 0, 0, &[0; 120], 1);
        assert_eq!(parse_packet(&legacy).unwrap().0.root_task_cookie, 0);
        let mut extended = legacy[..128].to_vec();
        extended.extend(77u64.to_le_bytes());
        extended.extend(&legacy[128..]);
        extended[6..8].copy_from_slice(&1u16.to_le_bytes());
        extended[8..10].copy_from_slice(&136u16.to_le_bytes());
        let size = extended.len() as u32;
        extended[12..16].copy_from_slice(&size.to_le_bytes());
        assert_eq!(parse_packet(&extended).unwrap().0.root_task_cookie, 77);
        for size in 128..136 {
            assert!(parse_packet(&extended[..size]).is_err());
        }
        extended[8..10].copy_from_slice(&128u16.to_le_bytes());
        assert!(parse_packet(&extended).is_err());
    }
    #[test]
    fn observer_extension_preserves_launch_owner_and_rejects_malformed_versions() {
        let legacy = packet(1, 0, 0, &[0; 120], 1);
        assert_eq!(parse_packet(&legacy).unwrap().0.capture_cookie, 0);
        let mut extended = legacy[..128].to_vec();
        extended.extend(77u64.to_le_bytes());
        extended.extend(91u64.to_le_bytes());
        extended.extend(&legacy[128..]);
        extended[6..8].copy_from_slice(&2u16.to_le_bytes());
        extended[8..10].copy_from_slice(&144u16.to_le_bytes());
        let size = extended.len() as u32;
        extended[12..16].copy_from_slice(&size.to_le_bytes());
        let (header, body) = parse_packet(&extended).unwrap();
        assert_eq!(header.root_task_cookie, 77);
        assert_eq!(header.capture_cookie, 91);
        assert_eq!(body, &legacy[128..]);
        for size in 128..144 {
            assert!(parse_packet(&extended[..size]).is_err());
        }
        extended[8..10].copy_from_slice(&136u16.to_le_bytes());
        assert!(parse_packet(&extended).is_err());
        extended[8..10].copy_from_slice(&144u16.to_le_bytes());
        extended[6..8].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_packet(&extended).is_err());
    }
    #[test]
    fn archived_object_symlink_and_fifo_never_become_captured_ranges() {
        let root =
            std::env::temp_dir().join(format!("ant-object-reader-{}", crate::storage::unique_id()));
        let objects = root.join("objects");
        private_dir(&objects).unwrap();
        let external = root.parent().unwrap().join(format!(
            "ant-object-external-{}",
            crate::storage::unique_id()
        ));
        std::fs::write(&external, b"abc").unwrap();
        let member = objects.join("0-0-0-1-0-1.raw");
        std::os::unix::fs::symlink(&external, &member).unwrap();
        let mut assembler = Assembler::open_archive(objects.clone()).unwrap();
        let event = assembler
            .ingest(&packet(3, 1, 0, b"abc", 1))
            .unwrap()
            .unwrap();
        assert!(event.fields[0].ranges.is_empty());
        assert!(event.issues.iter().any(|issue| issue.contains("escapes")));
        assert!(assembler.saving_error().is_none());
        std::fs::remove_file(&member).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&member)
                .status()
                .unwrap()
                .success()
        );
        let mut assembler = Assembler::open_archive(objects).unwrap();
        let event = assembler
            .ingest(&packet(3, 1, 0, b"abc", 1))
            .unwrap()
            .unwrap();
        assert!(event.fields[0].ranges.is_empty());
        assert!(assembler.saving_error().is_none());
        assert!(
            event
                .issues
                .iter()
                .any(|issue| issue.contains("regular file"))
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(external).unwrap();
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
    fn packet_sets_hold_any_number_of_packets_as_ranges() {
        let mut set = PacketSet::default();
        for seq in (1..=20_000u64).rev().filter(|seq| seq % 1000 != 0) {
            assert_eq!(set.insert(seq, &seq.to_le_bytes()), (false, false));
        }
        assert_eq!(set.len(), 19_980);
        assert_eq!(set.ranges.len(), 20);
        assert_eq!((set.first(), set.last()), (Some(1), Some(19_999)));
        assert!(set.fingerprints.len() <= FINGERPRINTED);
        // Filling the gaps joins the runs.
        for seq in (1000..20_000).step_by(1000) {
            set.insert(seq, b"gap");
        }
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 19_999);
        // A repeat is a duplicate; a fingerprinted one with other bytes conflicts.
        assert_eq!(set.insert(19_999, &19_999u64.to_le_bytes()), (true, false));
        assert_eq!(set.insert(19_999, b"other"), (true, true));
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
        assert!(
            s.issues
                .iter()
                .any(|issue| issue.ends_with("status COPY_FAULT"))
        );
        assert_eq!(status_name(12), "NOT_RESIDENT");
        assert_eq!(status_name(13), "UNKNOWN");
        assert!(a.saving_error().is_none());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn object_quota_and_io_failures_stop_saving_without_inventing_ranges() {
        for io_failure in [false, true] {
            let path = std::env::temp_dir()
                .join(format!("ant-object-saving-{}", crate::storage::unique_id()));
            let mut assembler = Assembler::new(path.clone(), 1024).unwrap();
            assembler.ingest(&packet(3, 1, 0, b"saved", 1)).unwrap();
            let retained = assembler.history()[0].fields[0].clone();
            let kept = crate::object_pack::FieldKey::parse(
                retained
                    .raw_path
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            if io_failure {
                // The next chunk needs a new segment, which cannot be created.
                assembler.pack.as_mut().unwrap().set_segment_size(10);
                std::fs::create_dir(path.join(crate::object_pack::segment_name(1))).unwrap();
            } else {
                assembler.set_storage_limit(6);
            }
            let event = assembler
                .ingest(&packet(3, 2, 0, b"not saved", 2))
                .unwrap()
                .unwrap();
            assert!(event.fields[1].ranges.is_empty());
            let failure = assembler.saving_error().unwrap().to_owned();
            assert!(failure.contains(if io_failure { "persistence" } else { "quota" }));
            assembler.set_storage_limit(1024);
            let event = assembler
                .ingest(&packet(3, 3, 0, b"later", 3))
                .unwrap()
                .unwrap();
            assert!(event.fields[2].ranges.is_empty());
            assert_eq!(assembler.saving_error(), Some(failure.as_str()));
            // Only the first chunk, its field and the index header were counted.
            use crate::object_pack::{CHUNK_RECORD_SIZE, FIELD_RECORD_SIZE, HEADER_SIZE};
            assert_eq!(
                assembler.stored_len(),
                5 + CHUNK_RECORD_SIZE + FIELD_RECORD_SIZE + HEADER_SIZE
            );
            assembler.pack.as_mut().unwrap().settle();
            assert_eq!(
                crate::object_pack::read_field_range(&path, &kept, 0, 5)
                    .unwrap()
                    .unwrap(),
                b"saved"
            );
            std::fs::remove_dir_all(path).unwrap();
        }
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
        a.pack.as_mut().unwrap().settle();
        let key = crate::object_pack::FieldKey::parse(
            event.fields[0]
                .raw_path
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let sample = crate::object_pack::read_field_range(&path, &key, 159 * 65536, 32)
            .unwrap()
            .unwrap();
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
