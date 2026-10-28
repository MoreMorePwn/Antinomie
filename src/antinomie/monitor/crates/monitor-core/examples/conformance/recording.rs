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
    /// Runs of a task's packet numbers that never arrived, with the guest
    /// timestamps of the packets on each side (the transport's drops,
    /// except those at the end of a task's numbering).
    pub dropped_packets: Vec<DroppedRange>,
}

/// Missing packets `first..=last` of one task's numbering.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
pub struct DroppedRange {
    pub task: u64,
    pub first: u64,
    pub last: u64,
    /// Guest timestamps of the packets before and after the run (0: unknown).
    /// A timestamp is when the packet's event began, which can be well before
    /// the packet was sent (the fragments of one event share it).
    pub before_ns: u64,
    pub after_ns: u64,
    /// Timestamp of the task's first later packet from another event than the
    /// one after the run (0: none yet): the run's drops happened before it.
    pub end_ns: u64,
    /// The vCPUs (rings) of the packets before and after the run.
    pub before_cpu: u32,
    pub after_cpu: u32,
    #[serde(skip)]
    after_event: u64,
}

/// The numbering seen so far of one task, and its still-missing runs.
#[derive(Default)]
struct Numbering {
    max: u64,
    max_ns: u64,
    max_cpu: u32,
    missing: Vec<DroppedRange>,
}

impl Numbering {
    /// A packet numbered `seq` at `ns`. Rings of different CPUs deliver a
    /// migrating task's packets out of order, so a missing run stays open
    /// until the end of the recording.
    fn see(&mut self, task: u64, seq: u64, ns: u64, event: u64, cpu: u32) {
        for run in self.missing.iter_mut().take(64) {
            if run.end_ns == 0 && run.after_event != event {
                run.end_ns = ns;
            }
        }
        if self.max == 0 || seq == self.max + 1 {
            (self.max, self.max_ns, self.max_cpu) = (seq, ns, cpu);
        } else if seq > self.max {
            self.missing.push(DroppedRange {
                task,
                first: self.max + 1,
                last: seq - 1,
                before_ns: self.max_ns,
                after_ns: ns,
                end_ns: 0,
                before_cpu: self.max_cpu,
                after_cpu: cpu,
                after_event: event,
            });
            (self.max, self.max_ns, self.max_cpu) = (seq, ns, cpu);
        } else if let Some(at) = self
            .missing
            .iter()
            .position(|r| (r.first..=r.last).contains(&seq))
        {
            let run = self.missing.remove(at);
            if seq > run.first {
                self.missing.push(DroppedRange {
                    last: seq - 1,
                    after_ns: ns,
                    ..run
                });
            }
            if seq < run.last {
                self.missing.push(DroppedRange {
                    first: seq + 1,
                    before_ns: ns,
                    ..run
                });
            }
        }
    }
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
    let mut numbering: BTreeMap<(u64, u64), Numbering> = BTreeMap::new();
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
                if header.packet_seq != 0 {
                    numbering
                        .entry((header.stream_id, header.task_cookie))
                        .or_default()
                        .see(
                            header.task_cookie,
                            header.packet_seq,
                            header.timestamp_ns,
                            header.call_id.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                ^ header.event_seq.rotate_left(17)
                                ^ u64::from(header.phase),
                            header.cpu,
                        );
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
    scan.dropped_packets = numbering.into_values().flat_map(|n| n.missing).collect();
    scan.dropped_packets
        .sort_by_key(|r| (r.before_ns, r.task, r.first));
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

#[cfg(test)]
mod numbering_tests {
    use super::*;

    fn runs(order: &[(u64, u64)]) -> Vec<(u64, u64, u64, u64)> {
        let mut numbering = Numbering::default();
        for &(seq, ns) in order {
            // Each packet is an event of its own.
            numbering.see(9, seq, ns, seq, 0);
        }
        let mut found: Vec<_> = numbering
            .missing
            .iter()
            .map(|r| (r.first, r.last, r.before_ns, r.after_ns))
            .collect();
        found.sort();
        found
    }

    #[test]
    fn a_complete_numbering_misses_nothing() {
        assert!(runs(&[(1, 10), (2, 20), (3, 30)]).is_empty());
    }

    #[test]
    fn a_skipped_run_is_bounded_by_its_neighbours_timestamps() {
        assert_eq!(
            runs(&[(1, 10), (2, 20), (5, 500), (6, 510)]),
            [(3, 4, 20, 500)]
        );
    }

    #[test]
    fn a_run_ends_at_the_next_event_of_the_task() {
        let mut numbering = Numbering::default();
        // Packets 4 and 5 are fragments of event 40; 6 is the next event.
        numbering.see(9, 1, 10, 10, 0);
        numbering.see(9, 4, 40, 40, 2);
        numbering.see(9, 5, 40, 40, 2);
        assert_eq!(numbering.missing[0].end_ns, 0);
        numbering.see(9, 6, 900, 60, 1);
        let run = numbering.missing[0];
        assert_eq!((run.before_ns, run.after_ns, run.end_ns), (10, 40, 900));
        assert_eq!((run.before_cpu, run.after_cpu), (0, 2));
    }

    #[test]
    fn packets_arriving_out_of_order_close_their_run() {
        assert!(runs(&[(1, 10), (4, 40), (3, 35), (2, 30)]).is_empty());
        // The middle of three missing packets arrives late: two runs remain.
        assert_eq!(
            runs(&[(1, 10), (5, 50), (3, 30)]),
            [(2, 2, 10, 30), (4, 4, 30, 50)]
        );
    }
}
