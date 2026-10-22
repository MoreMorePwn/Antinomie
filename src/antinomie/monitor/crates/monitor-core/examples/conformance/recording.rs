// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A run's recording as the application reads it, plus a raw scan of its
//! packets so every record can be accounted for.
use antinomie_monitor_core::{InvocationSummary, parser, recording};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

/// Counts from reading `telemetry.raw` packet by packet.
#[derive(Debug, Default, serde::Serialize)]
pub struct RawScan {
    pub packets: u64,
    pub framing_error: Option<String>,
    /// Packets the application's parser rejects, by error.
    pub parse_errors: BTreeMap<String, u64>,
    /// Distinct events (stream, task, call, phase, event_seq) with packets.
    pub events: u64,
    /// Events whose EVENT_END says packets of them failed to send.
    pub events_reporting_loss: u64,
    /// Packets the recorder attempted for the events whose EVENT_END arrived,
    /// minus those that arrived: records the transport lost.
    pub packets_missing_by_end: u64,
    /// Events whose EVENT_END never arrived.
    pub events_without_end: u64,
    /// Recorder health packets (record type 2).
    pub health_packets: u64,
    /// Async requests seen (by request id), those with no final record, and
    /// those whose final record still says the payload was not observed and
    /// that no later reaped record completed.
    pub async_requests: u64,
    pub async_without_final: u64,
    pub async_payload_missing: u64,
    /// io_uring requests whose submission says who wrote the entry
    /// (`async.flags`): a thread of the submitting process (bit 3), or a
    /// writer that is not proven (bit 1).
    pub async_producer_process: u64,
    pub async_producer_unknown: u64,
}

/// What the scan keeps of one async request.
#[derive(Default)]
struct Request {
    final_seen: bool,
    final_gap: bool,
    reaped: bool,
    /// `async.flags` of the submission record (stage 1).
    submitted_flags: Option<u64>,
}

const ASYNC_KEYS: [&str; 4] = [
    "async.request_id",
    "async.stage",
    "async.final",
    "async.flags",
];

/// (stream, task, call, phase, event_seq).
type EventKey = (u64, u64, u64, u8, u64);
/// Packets seen, and (attempted, failed) from the event's END.
type EventCount = (u64, Option<(u64, u64)>);

/// Read every packet of the recording; bounded per packet, not per file.
pub fn scan_raw(directory: &Path) -> Result<RawScan, String> {
    let file = File::open(directory.join("telemetry.raw")).map_err(|e| e.to_string())?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut scan = RawScan::default();
    // Per event: packets seen, and the attempted count its END reports.
    let mut events: BTreeMap<EventKey, EventCount> = BTreeMap::new();
    // Async scalars by event, then by key: (object id → key index), values.
    let mut objects: BTreeMap<(u64, u64, u64, u64, u32), usize> = BTreeMap::new();
    let mut scalars: BTreeMap<(u64, u64, u64, u64), [Option<u64>; 4]> = BTreeMap::new();
    let mut packet = Vec::new();
    loop {
        let mut prefix = [0u8; 4];
        match reader.read(&mut prefix[..1]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
        if let Err(error) = reader.read_exact(&mut prefix[1..]) {
            scan.framing_error = Some(format!("truncated packet prefix: {error}"));
            break;
        }
        let size = u32::from_le_bytes(prefix) as usize;
        if !(128..=262_112).contains(&size) {
            scan.framing_error = Some(format!("packet length {size} out of range"));
            break;
        }
        packet.resize(size, 0);
        if let Err(error) = reader.read_exact(&mut packet) {
            scan.framing_error = Some(format!("truncated packet: {error}"));
            break;
        }
        scan.packets += 1;
        match parser::parse_packet(&packet) {
            Ok((header, body)) => {
                if header.record_type == 2 {
                    scan.health_packets += 1;
                    continue;
                }
                let key = (
                    header.stream_id,
                    header.task_cookie,
                    header.call_id,
                    header.phase,
                    header.event_seq,
                );
                if header.phase == 3 {
                    let event = (
                        header.stream_id,
                        header.task_cookie,
                        header.call_id,
                        header.event_seq,
                    );
                    let object = (event.0, event.1, event.2, event.3, header.object_id);
                    if header.fragment == 2 && body.len() >= 40 {
                        let key_len = usize::from(u16::from_le_bytes([body[32], body[33]]));
                        let key = body.get(40..40 + key_len).unwrap_or_default();
                        if let Some(index) = ASYNC_KEYS.iter().position(|k| k.as_bytes() == key) {
                            objects.insert(object, index);
                        }
                    } else if header.fragment == 3
                        && header.object_offset == 0
                        && body.len() == 8
                        && let Some(&index) = objects.get(&object)
                    {
                        let value = u64::from_le_bytes(body.try_into().unwrap_or([0; 8]));
                        scalars.entry(event).or_default()[index] = Some(value);
                    }
                }
                let entry = events.entry(key).or_default();
                entry.0 += 1;
                if header.fragment == 5 && body.len() == 32 {
                    let at = |offset: usize| {
                        u64::from_le_bytes(body[offset..offset + 8].try_into().unwrap_or([0; 8]))
                    };
                    entry.1 = Some((at(8), at(16)));
                }
            }
            Err(error) => *scan.parse_errors.entry(error.to_string()).or_default() += 1,
        }
    }
    let mut requests: BTreeMap<u64, Request> = BTreeMap::new();
    for values in scalars.values() {
        let [Some(id), Some(stage), Some(last), flags] = *values else {
            continue;
        };
        let request = requests.entry(id).or_default();
        if last == 1 {
            request.final_seen = true;
            request.final_gap = flags.unwrap_or(0) & 1 != 0;
        }
        request.reaped |= stage == 7;
        if stage == 1 {
            request.submitted_flags = flags;
        }
    }
    scan.async_producer_process = requests
        .values()
        .filter(|r| r.submitted_flags.is_some_and(|flags| flags & 8 != 0))
        .count() as u64;
    scan.async_producer_unknown = requests
        .values()
        .filter(|r| r.submitted_flags.is_some_and(|flags| flags & 2 != 0))
        .count() as u64;
    scan.async_requests = requests.len() as u64;
    scan.async_without_final = requests.values().filter(|r| !r.final_seen).count() as u64;
    scan.async_payload_missing = requests
        .values()
        .filter(|r| r.final_seen && r.final_gap && !r.reaped)
        .count() as u64;
    scan.events = events.len() as u64;
    for (seen, end) in events.values() {
        match end {
            Some((attempted, failed)) => {
                scan.packets_missing_by_end += attempted.saturating_sub(*seen);
                scan.events_reporting_loss += u64::from(*failed != 0);
            }
            None => scan.events_without_end += 1,
        }
    }
    Ok(scan)
}

/// Every invocation of the recording, in recording order, and the page
/// diagnostics the application would show.
pub fn invocations(directory: &Path) -> Result<(Vec<InvocationSummary>, BTreeSet<String>), String> {
    let archive = recording::open_recording(directory).map_err(|e| e.to_string())?;
    let mut all = Vec::new();
    let mut issues = BTreeSet::new();
    let mut cursor = Some(0);
    while let Some(offset) = cursor {
        let page = archive
            .invocation_page(offset, 256)
            .map_err(|e| e.to_string())?;
        issues.extend(page.issues);
        all.extend(page.invocations);
        cursor = page.next_offset;
    }
    Ok((all, issues))
}

/// Visit every invocation page by page without keeping them (stress runs).
pub fn for_each_invocation(
    directory: &Path,
    mut visit: impl FnMut(&InvocationSummary),
) -> Result<BTreeSet<String>, String> {
    let archive = recording::open_recording(directory).map_err(|e| e.to_string())?;
    let mut issues = BTreeSet::new();
    let mut cursor = Some(0);
    while let Some(offset) = cursor {
        let page = archive
            .invocation_page(offset, 256)
            .map_err(|e| e.to_string())?;
        issues.extend(page.issues);
        for call in &page.invocations {
            visit(call);
        }
        cursor = page.next_offset;
    }
    Ok(issues)
}

/// The run's terminal output as the program wrote it.
pub fn transcript(directory: &Path) -> Result<String, String> {
    std::fs::read(directory.join("terminal-transcript.raw"))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| format!("terminal transcript: {e}"))
}
