// SPDX-License-Identifier: GPL-3.0-only
//! io_uring and AIO file requests, read as the system calls they stand for.
//!
//! Triage follows files through system calls, and a program that does its file
//! work through an io_uring ring or an AIO context makes almost none: the
//! work is requested with a few `io_uring_enter` or `io_submit` calls and done
//! by worker threads or later. The guest records each request as asynchronous
//! observations of the submitting call: the submission queue entry (or I/O
//! control block) exactly as the program wrote it, the path operands it
//! named, the data moved, the result, and the identity of the file the request
//! used (`async.operand.file_id`).
//!
//! This module groups those observations by request and writes each file
//! request as the equivalent system call: `IORING_OP_OPENAT` is an `openat`
//! whose result is the new descriptor, `IORING_OP_WRITE` a `write` or
//! `pwrite64` of the recorded bytes, `IORING_OP_UNLINKAT` an `unlinkat`, and so
//! on. The rest of Triage (descriptor tracking, the Opened, Read, Written,
//! Deleted and Renamed tabs, per-file lifecycles, detection events) then needs
//! no second code path. The call keeps the submitting call's identity, so its
//! evidence is the `io_uring_enter` that carried the request.
//!
//! Nothing is invented. A request with no completion has no result; a path the
//! guest could not record is missing, not guessed; a descriptor of a registered
//! file table is resolved only through the file identity the guest recorded.
//! Operations that do not touch a file (`IORING_OP_POLL_ADD`, sockets, timeouts)
//! produce no call. Requests whose observations the scan did not read are
//! counted in the coverage line.
use super::*;
use antinomie_monitor_core::{kernel_notes, FieldSummary};

/// `io_uring_enter` and `io_submit` on x86-64: the calls that carry requests.
/// `io_uring_setup`: the call that makes a ring.
/// Most requests turned into calls per scan: the scan must stay bounded.
pub(super) const REQUEST_LIMIT: usize = 100_000;
/// Observations read per archive page.
const PAGE: usize = 256;

/// `-1` as the offset of a request that uses the file position.
const CURRENT_POSITION: u64 = u64::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
enum System {
    IoUring,
    Aio,
}

/// Everything the guest recorded about one request.
struct Request {
    system: System,
    opcode: u32,
    /// The submission entry or control block as written.
    sqe: Vec<u8>,
    first: EventSummary,
    last_seq: u64,
    done_ns: Option<u64>,
    result: Option<i64>,
    operands: Vec<FieldSummary>,
    /// The data the request moved, by its offset in the transfer: the guest
    /// publishes a transfer in stages (a vector read fills one segment after
    /// another).
    input: Vec<(u64, FieldSummary)>,
    output: Vec<(u64, FieldSummary)>,
    complete: bool,
}

fn scalar(event: &EventSummary, key: &str) -> Option<u64> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    Some(u64::from_le_bytes(field.preview.get(..8)?.try_into().ok()?))
}

fn text(event: &EventSummary, key: &str) -> Option<String> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    let end = field.preview.iter().position(|byte| *byte == 0)?;
    String::from_utf8(field.preview[..end].to_vec()).ok()
}

/// The requests of `events`, in the order they were submitted.
fn requests(events: &[EventSummary]) -> Vec<Request> {
    let mut found: Vec<Request> = Vec::new();
    let mut index = std::collections::BTreeMap::new();
    for event in events {
        let Some(id) = scalar(event, "async.request_id") else {
            continue;
        };
        let at = *index.entry(id).or_insert_with(|| {
            found.push(Request {
                system: System::IoUring,
                opcode: u32::MAX,
                sqe: Vec::new(),
                first: event.clone(),
                last_seq: event.event_seq,
                done_ns: None,
                result: None,
                operands: Vec::new(),
                input: Vec::new(),
                output: Vec::new(),
                complete: true,
            });
            found.len() - 1
        });
        let request = &mut found[at];
        request.last_seq = request.last_seq.max(event.event_seq);
        if event.timestamp_ns < request.first.timestamp_ns {
            request.first.timestamp_ns = event.timestamp_ns;
        }
        match text(event, "async.system").as_deref() {
            Some("AIO") => request.system = System::Aio,
            Some("io_uring") => request.system = System::IoUring,
            _ => {}
        }
        if let Some(opcode) = scalar(event, "async.opcode") {
            request.opcode = opcode as u32;
        }
        // 3 rejected, 4 completed, 5 canceled, 6 abandoned (no result).
        if let Some(3..=5) = scalar(event, "async.stage") {
            request.result = scalar(event, "async.result").map(|raw| raw as i64);
            request.done_ns = Some(event.timestamp_ns);
        }
        let offset = scalar(event, "async.payload.result_offset").unwrap_or(0);
        for field in &event.fields {
            match field.key.as_str() {
                "async.submission" if request.sqe.is_empty() => {
                    request.sqe = trace::covered_preview(field).to_vec();
                }
                "async.payload.input" => stage(&mut request.input, offset, field),
                "async.payload.output" => stage(&mut request.output, offset, field),
                key if key.starts_with("async.operand.")
                    && !request.operands.iter().any(|known| known.key == key) =>
                {
                    request.operands.push(field.clone());
                }
                _ => {}
            }
        }
    }
    found
}

/// Keep one stage of a request's data per offset (the first that has bytes),
/// at most 64 per request.
fn stage(stages: &mut Vec<(u64, FieldSummary)>, offset: u64, field: &FieldSummary) {
    if field.logical_len == Some(0) || stages.len() >= 64 {
        return;
    }
    if !stages.iter().any(|(known, _)| *known == offset) {
        stages.push((offset, field.clone()));
    }
}

/// The data of a request as the buffer of the call it stands for: one stage
/// at offset 0 is `arg1.buf`; several are the segments `arg1.iov[N].data`, in
/// order, up to the first stage that is missing (the rest stays unknown).
fn buffer_fields(stages: &[(u64, FieldSummary)]) -> Vec<FieldSummary> {
    let mut sorted: Vec<&(u64, FieldSummary)> = stages.iter().collect();
    sorted.sort_by_key(|(offset, _)| *offset);
    if let [(0, only)] = sorted.as_slice() {
        return vec![captured("arg1.buf".into(), "", only)];
    }
    let mut fields = Vec::new();
    let mut next = 0u64;
    for (offset, field) in sorted {
        if *offset != next {
            break;
        }
        fields.push(captured(
            format!("arg1.iov[{}].data", fields.len()),
            "",
            field,
        ));
        match field
            .logical_len
            .and_then(|length| next.checked_add(length))
        {
            Some(end) => next = end,
            None => break,
        }
    }
    fields
}

fn byte(sqe: &[u8], at: usize) -> u64 {
    sqe.get(at).copied().map_or(0, u64::from)
}
fn le<const N: usize>(sqe: &[u8], at: usize) -> u64 {
    sqe.get(at..at + N).map_or(0, |bytes| {
        let mut wide = [0u8; 8];
        wide[..N].copy_from_slice(bytes);
        u64::from_le_bytes(wide)
    })
}
/// A descriptor argument as a system call carries it: sign extended.
fn descriptor(value: u64) -> u64 {
    i64::from(value as u32 as i32) as u64
}

/// The system call a request stands for.
struct Equivalent {
    nr: u64,
    name: &'static str,
    args: [u64; 6],
    /// `(argument index, operand)` of every path the call names.
    paths: Vec<(usize, &'static str)>,
    /// The request's data is a `buf` argument: written (entry) or read (exit).
    writes: bool,
    reads: bool,
    /// An open that installs the file in the ring's registered table: its
    /// result is a slot of that table (or 0), never a descriptor of the process.
    direct: bool,
    /// The extended attribute value the request set (argument 2).
    value: bool,
}

impl Equivalent {
    fn new(name: &'static str, args: [u64; 6]) -> Self {
        Self::numbered(syscalls::number(name).unwrap_or(u64::MAX), name, args)
    }
    fn numbered(nr: u64, name: &'static str, args: [u64; 6]) -> Self {
        Self {
            nr,
            name,
            args,
            paths: Vec::new(),
            writes: false,
            reads: false,
            direct: false,
            value: false,
        }
    }
    fn path(mut self, index: usize, operand: &'static str) -> Self {
        self.paths.push((index, operand));
        self
    }
}

/// `IORING_FSYNC_DATASYNC`: the request is an `fdatasync`.
const FSYNC_DATASYNC: u64 = 1;
/// `SPLICE_F_FD_IN_FIXED`: the input of a splice is a registered descriptor.
const SPLICE_FD_IN_FIXED: u64 = 1 << 31;

/// Positioned or sequential data transfer of a descriptor.
fn transfer(sqe: &[u8], write: bool, vector: bool, offset: u64) -> Equivalent {
    let fd = if byte(sqe, 1) & 1 != 0 {
        u64::MAX
    } else {
        descriptor(le::<4>(sqe, 4))
    };
    let buffer = le::<8>(sqe, 16);
    let length = le::<4>(sqe, 24);
    let positioned = offset != CURRENT_POSITION;
    let name = match (write, vector, positioned) {
        (false, false, false) => "read",
        (false, false, true) => "pread64",
        (false, true, false) => "readv",
        (false, true, true) => "preadv",
        (true, false, false) => "write",
        (true, false, true) => "pwrite64",
        (true, true, false) => "writev",
        (true, true, true) => "pwritev",
    };
    let mut args = [fd, buffer, length, 0, 0, 0];
    if positioned {
        args[3] = offset;
    }
    let mut call = Equivalent::new(name, args);
    call.writes = write;
    call.reads = !write;
    call
}

fn uring(request: &Request) -> Option<Equivalent> {
    let sqe = &request.sqe;
    let off = le::<8>(sqe, 8);
    let addr = le::<8>(sqe, 16);
    let len = le::<4>(sqe, 24);
    let flags = le::<4>(sqe, 28);
    // A registered descriptor is an index into the ring's table, not a number
    // of the process: it must not be taken for the descriptor of that number.
    // Only the file identity the guest recorded can say which file it is.
    let fixed = byte(sqe, 1) & 1 != 0;
    let fd = if fixed {
        u64::MAX
    } else {
        descriptor(le::<4>(sqe, 4))
    };
    let mut call = match request.opcode {
        1 => transfer(sqe, false, true, off),
        4 | 22 | 49 => transfer(sqe, false, false, off),
        2 => transfer(sqe, true, true, off),
        5 | 23 => transfer(sqe, true, false, off),
        18 => Equivalent::new("openat", [fd, addr, flags, len, 0, 0]).path(1, "path"),
        28 => Equivalent::new("openat2", [fd, addr, off, len, 0, 0]).path(1, "path"),
        19 if le::<4>(sqe, 44) == 0 => Equivalent::new("close", [fd, 0, 0, 0, 0, 0]),
        55 => Equivalent::new("ftruncate", [fd, off, 0, 0, 0, 0]),
        17 => Equivalent::new("fallocate", [fd, len, off, addr, 0, 0]),
        35 => Equivalent::new("renameat2", [fd, addr, descriptor(len), off, flags, 0])
            .path(1, "oldpath")
            .path(3, "newpath"),
        36 => Equivalent::new("unlinkat", [fd, addr, flags, 0, 0, 0]).path(1, "path"),
        37 => Equivalent::new("mkdirat", [fd, addr, len, 0, 0, 0]).path(1, "path"),
        38 => Equivalent::new("symlinkat", [addr, fd, off, 0, 0, 0])
            .path(0, "oldpath")
            .path(2, "newpath"),
        39 => Equivalent::new("linkat", [fd, addr, descriptor(len), off, flags, 0])
            .path(1, "oldpath")
            .path(3, "newpath"),
        21 => Equivalent::new("statx", [fd, addr, flags, len, off, 0]).path(1, "path"),
        3 if flags & FSYNC_DATASYNC != 0 => Equivalent::new("fdatasync", [fd, 0, 0, 0, 0, 0]),
        3 => Equivalent::new("fsync", [fd, 0, 0, 0, 0, 0]),
        8 => Equivalent::new("sync_file_range", [fd, off, len, flags, 0, 0]),
        // The offsets of a request are values (-1: the file position), not
        // pointers to them as for the system call: the call carries none.
        30 => {
            let input = if flags & SPLICE_FD_IN_FIXED != 0 {
                u64::MAX
            } else {
                descriptor(le::<4>(sqe, 44))
            };
            Equivalent::new("splice", [input, 0, fd, 0, len, flags])
        }
        41 => Equivalent::new("fsetxattr", [fd, addr, off, len, flags, 0]).path(1, "xattr_name"),
        42 => Equivalent::new("setxattr", [le::<8>(sqe, 48), addr, off, len, flags, 0])
            .path(0, "path")
            .path(1, "xattr_name"),
        43 => Equivalent::new("fgetxattr", [fd, addr, off, len, 0, 0]).path(1, "xattr_name"),
        44 => Equivalent::new("getxattr", [le::<8>(sqe, 48), addr, off, len, 0, 0])
            .path(0, "path")
            .path(1, "xattr_name"),
        _ => return None,
    };
    // The value an attribute is set to is the data the request wrote.
    call.value = matches!(request.opcode, 41 | 42);
    if fixed && !call.reads && !call.writes {
        call.args[0] = u64::MAX;
    }
    // `file_index` of an open: the file goes into the registered table.
    call.direct = matches!(request.opcode, 18 | 28) && le::<4>(sqe, 44) != 0;
    Some(call)
}

fn aio(request: &Request) -> Option<Equivalent> {
    let sqe = &request.sqe;
    let fd = le::<4>(sqe, 20);
    let buffer = le::<8>(sqe, 24);
    let length = le::<8>(sqe, 32);
    let offset = le::<8>(sqe, 40);
    // IOCB_CMD_PREAD, PWRITE, PREADV, PWRITEV.
    let mut call = match request.opcode {
        0 => Equivalent::new("pread64", [fd, buffer, length, offset, 0, 0]),
        1 => Equivalent::new("pwrite64", [fd, buffer, length, offset, 0, 0]),
        7 => Equivalent::new("preadv", [fd, buffer, length, offset, 0, 0]),
        8 => Equivalent::new("pwritev", [fd, buffer, length, offset, 0, 0]),
        _ => return None,
    };
    call.reads = matches!(request.opcode, 0 | 7);
    call.writes = !call.reads;
    Some(call)
}

/// The field that tells a call was an asynchronous request: the system that
/// carried it. Syscalls the guest traced never have it.
const VIA_KEY: &str = "async.system";
/// The field that marks an open into the ring's registered file table.
const DIRECT_KEY: &str = "async.direct_descriptor";

fn via_field(system: System) -> FieldSummary {
    let label: &[u8] = match system {
        System::IoUring => b"io_uring\0",
        System::Aio => b"AIO\0",
    };
    FieldSummary {
        arg: None,
        object_id: 0,
        key: VIA_KEY.into(),
        layout: String::new(),
        logical_len: Some(label.len() as u64),
        captured_len: label.len() as u64,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: label.to_vec(),
        raw_path: None,
        ranges: vec![(0, label.len() as u64)],
        recapture: None,
        encoding: None,
    }
}

/// Whether the call is an io_uring open that put the file in the ring's
/// registered table: its result names no descriptor of the process, so it
/// must not be tracked as one. Later requests on that slot reach the file
/// through the identity the guest recorded for them.
pub(super) fn direct_descriptor(call: &InvocationSummary) -> bool {
    call.entry
        .as_ref()
        .is_some_and(|entry| entry.fields.iter().any(|field| field.key == DIRECT_KEY))
}

/// `io_uring` or `AIO` for a call that stands for an asynchronous request, and
/// `None` for a system call the guest traced itself.
pub(super) fn via(call: &InvocationSummary) -> Option<&'static str> {
    let field = call
        .entry
        .as_ref()?
        .fields
        .iter()
        .find(|field| field.key == VIA_KEY)?;
    match field.preview.first() {
        Some(b'i') => Some("io_uring"),
        Some(b'A') => Some("AIO"),
        _ => None,
    }
}

fn captured(key: String, layout: &str, source: &FieldSummary) -> FieldSummary {
    FieldSummary {
        key,
        layout: layout.into(),
        ..source.clone()
    }
}

fn event_for(
    parent: &EventSummary,
    request: &Request,
    equivalent: &Equivalent,
    phase: u8,
) -> EventSummary {
    let at = if phase == 1 {
        request.first.timestamp_ns
    } else {
        request.done_ns.unwrap_or(request.first.timestamp_ns)
    };
    EventSummary {
        root_task_cookie: parent.root_task_cookie,
        stream_id: parent.stream_id,
        task_cookie: parent.task_cookie,
        call_id: parent.call_id,
        event_seq: if phase == 1 {
            request.first.event_seq
        } else {
            request.last_seq
        },
        phase,
        syscall_nr: equivalent.nr,
        syscall_name: equivalent.name.into(),
        pid: parent.pid,
        tid: parent.tid,
        cpu: parent.cpu,
        timestamp_ns: at,
        args: (phase == 1).then_some(equivalent.args),
        result: (phase == 2).then_some(request.result).flatten(),
        complete: request.complete,
        issues: Vec::new(),
        fields: Vec::new(),
    }
}

/// The identity record of a request, as the note a call would carry.
fn identity_note(parent: &EventSummary, request: &Request) -> Option<EventSummary> {
    let field = request
        .operands
        .iter()
        .find(|field| kernel_notes::file_id_operand(field).is_some())?;
    let mut note = event_for(
        parent,
        request,
        &Equivalent::numbered(parent.syscall_nr, "", [0; 6]),
        3,
    );
    note.syscall_name = parent.syscall_name.clone();
    note.fields.push(captured(
        kernel_notes::FILE_ID_KEY.into(),
        kernel_notes::FILE_ID_LAYOUT,
        field,
    ));
    Some(note)
}

/// The call a request stands for, or `None` for one that touches no file.
fn call_for(parent: &InvocationSummary, request: &Request) -> Option<InvocationSummary> {
    let template = trace::representative(parent)?;
    let equivalent = match request.system {
        System::IoUring => uring(request)?,
        System::Aio => aio(request)?,
    };
    if request.sqe.is_empty() {
        return None;
    }
    let mut entry = event_for(template, request, &equivalent, 1);
    let mut exit = event_for(template, request, &equivalent, 2);
    entry.fields.push(via_field(request.system));
    if equivalent.direct {
        entry.fields.push(FieldSummary {
            key: DIRECT_KEY.into(),
            ..via_field(request.system)
        });
    }
    for (index, operand) in &equivalent.paths {
        if let Some(path) = request
            .operands
            .iter()
            .find(|field| field.key == format!("async.operand.{operand}"))
        {
            let name = trace::argument_name(equivalent.nr, *index);
            entry
                .fields
                .push(captured(format!("arg{index}.{name}"), "", path));
        }
    }
    if equivalent.name == "openat2" {
        // The flags are the first word of the `open_how` the request pointed to.
        if let Some(how) = request
            .operands
            .iter()
            .find(|field| field.key == "async.operand.open_how")
        {
            entry
                .fields
                .push(captured("arg2.how.flags".into(), "", how));
        }
    }
    if equivalent.writes {
        entry.fields.extend(buffer_fields(&request.input));
    }
    if equivalent.value
        && let Some(value) = request
            .operands
            .iter()
            .find(|field| field.key == "async.operand.xattr_value")
    {
        let name = trace::argument_name(equivalent.nr, 2);
        entry
            .fields
            .push(captured(format!("arg2.{name}"), "", value));
    }
    if equivalent.reads {
        exit.fields.extend(buffer_fields(&request.output));
    }
    Some(InvocationSummary {
        stream_id: parent.stream_id,
        task_cookie: parent.task_cookie,
        call_id: parent.call_id,
        entry: Some(entry),
        exit: request.result.is_some().then_some(exit),
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: identity_note(template, request).into_iter().collect(),
    })
}

/// Whether the call is one that carries requests.
fn submits(call: &InvocationSummary) -> bool {
    trace::representative(call)
        .is_some_and(|event| matches!(event.syscall_name.as_str(), "io_uring_enter" | "io_submit"))
}

/// The calls the requests of `events` stand for, with the submitting call's
/// identity.
pub(super) fn calls(parent: &InvocationSummary, events: &[EventSummary]) -> Vec<InvocationSummary> {
    if !submits(parent) {
        return Vec::new();
    }
    requests(events)
        .iter()
        .filter_map(|request| call_for(parent, request))
        .collect()
}

/// File requests that no call of their process submitted: those of an
/// SQPOLL ring's `iou-sqp` thread, or of a process the ring was passed to.
/// The guest attributes them to the task that made the ring, with call id 0
/// (contract 14.3), so they are read once per such task, after its first
/// ring is made, and stand for calls of that task (its descriptors, its
/// evidence: the `io_uring_setup`), each at the time of its first record. The
/// scan holds them until the calls it walks reach that time.
#[derive(Default)]
pub(super) struct Attributed {
    /// Tasks whose attributed requests were read: stream and task cookie.
    read: std::collections::BTreeSet<(u64, u64)>,
    /// Calls not yet due, by segment, time and the order they were read.
    waiting: std::collections::BTreeMap<(usize, u64, u64), InvocationSummary>,
    order: u64,
}

impl Attributed {
    /// After `setup` made a ring: read every request attributed to its task.
    pub(super) fn read(
        &mut self,
        recording: &antinomie_monitor_core::recording::Recording,
        segment: usize,
        setup: &InvocationSummary,
        reach: &mut Reach,
        cancel: &AtomicBool,
    ) {
        let made = trace::representative(setup).is_some_and(|event| {
            event.syscall_name == "io_uring_setup"
                && setup
                    .exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .is_some_and(|result| result >= 0)
        });
        if !made || !self.read.insert((setup.stream_id, setup.task_cookie)) {
            return;
        }
        let mut events = Vec::new();
        let mut from = 0;
        loop {
            if reach.requests >= REQUEST_LIMIT || events.len() >= REQUEST_LIMIT * 8 {
                reach.unread_calls += 1;
                break;
            }
            match recording.attributed_async_page_cancellable(
                setup.stream_id,
                setup.task_cookie,
                from,
                PAGE,
                cancel,
            ) {
                Ok(page) => {
                    events.extend(page.events);
                    match page.next_event_seq {
                        Some(next) => from = next,
                        None => break,
                    }
                }
                Err(_) => {
                    reach.unread_calls += 1;
                    break;
                }
            }
        }
        self.hold(segment, setup, &events, reach);
    }

    /// Hold the calls the attributed `events` of `setup`'s task stand for.
    pub(super) fn hold(
        &mut self,
        segment: usize,
        setup: &InvocationSummary,
        events: &[EventSummary],
        reach: &mut Reach,
    ) {
        for request in requests(events) {
            if reach.requests >= REQUEST_LIMIT {
                reach.unread_requests += 1;
                continue;
            }
            if let Some(call) = call_for(setup, &request) {
                reach.requests += 1;
                let at = call.entry.as_ref().map_or(0, |entry| entry.timestamp_ns);
                self.order += 1;
                self.waiting.insert((segment, at, self.order), call);
            }
        }
    }

    /// The calls due before `call` of `segment`: all of an earlier segment,
    /// and those of this one recorded no later than the call.
    pub(super) fn due(
        &mut self,
        segment: usize,
        call: &InvocationSummary,
    ) -> Vec<InvocationSummary> {
        let Some(at) = trace::representative(call).map(|event| event.timestamp_ns) else {
            return Vec::new();
        };
        let later = self.waiting.split_off(&(segment, at, u64::MAX));
        std::mem::replace(&mut self.waiting, later)
            .into_values()
            .collect()
    }

    /// The calls still held when the walk ended, with their segment.
    pub(super) fn rest(&mut self) -> Vec<(usize, InvocationSummary)> {
        std::mem::take(&mut self.waiting)
            .into_iter()
            .map(|((segment, _, _), call)| (segment, call))
            .collect()
    }
}

/// What reading the observations of a call left out.
#[derive(Default)]
pub(super) struct Reach {
    /// Requests turned into calls.
    pub requests: usize,
    /// Calls whose observations could not all be read.
    pub unread_calls: u64,
    pub unread_requests: u64,
}

/// Every file request of one call: the preview it carries, and the pages after
/// it when the call has more saved observations than the preview holds.
pub(super) fn expand(
    recording: &antinomie_monitor_core::recording::Recording,
    parent: &InvocationSummary,
    reach: &mut Reach,
    cancel: &AtomicBool,
) -> Vec<InvocationSummary> {
    if (parent.async_saved == 0 && parent.async_events.is_empty()) || !submits(parent) {
        return Vec::new();
    }
    if reach.requests >= REQUEST_LIMIT {
        reach.unread_calls += 1;
        reach.unread_requests += parent.async_saved.max(parent.async_events.len() as u64);
        return Vec::new();
    }
    let mut events = parent.async_events.clone();
    if parent.async_omitted() > 0 {
        let key = trace::key(parent);
        let mut from = 0;
        events.clear();
        loop {
            match recording.async_page_cancellable(key, from, PAGE, cancel) {
                Ok(page) => {
                    events.extend(page.events);
                    match page.next_event_seq {
                        Some(next) if events.len() < REQUEST_LIMIT * 8 => from = next,
                        Some(_) => {
                            reach.unread_calls += 1;
                            break;
                        }
                        None => break,
                    }
                }
                Err(_) => {
                    reach.unread_calls += 1;
                    reach.unread_requests += parent.async_omitted();
                    break;
                }
            }
        }
    }
    let calls = calls(parent, &events);
    reach.requests += calls.len();
    #[cfg(test)]
    if std::env::var_os("ANTINOMIE_URING_DUMP").is_some() {
        for call in &calls {
            let entry = call.entry.as_ref().unwrap();
            eprintln!(
                "async call {} {:x?} -> {:?} via {:?} paths {:?} id {:?}",
                entry.syscall_name,
                entry.args.unwrap(),
                call.exit.as_ref().and_then(|exit| exit.result),
                via(call),
                path_list(call),
                kernel_records::file_id(call).map(|id| (id.kind, id.key.ino, id.nlink)),
            );
        }
    }
    calls
}
