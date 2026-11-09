// SPDX-License-Identifier: GPL-3.0-only
//! Engine call records to the API's trace objects (design 5.12.3 `TraceRow`,
//! `Invocation`, `Event`, `Field`). Identifiers that can pass 2^53 are decimal
//! strings; registers are `0x` hex; engine text has host paths removed.

use super::{scrub::Scrub, types::*};
use antinomie_monitor_core::{
    EventSummary, FieldSummary, InvocationSummary, WaitStatus, syscall_groups::SyscallGroup,
};

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, for byte replies and previews.
pub fn base64(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                text.push(STD[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                text.push('=');
            }
        }
    }
    text
}

/// `0x` and lower-case hex.
pub fn hex(value: u64) -> Hex {
    format!("{value:#x}")
}

pub fn call_ref(call: &InvocationSummary) -> CallRef {
    CallRef {
        stream: U64(call.stream_id),
        task: U64(call.task_cookie),
        call: U64(call.call_id),
    }
}

/// The group of a call; a name outside the native table (compat ABIs) is `info`.
pub fn group_of(name: &str) -> SyscallGroupName {
    SyscallGroup::of(name).map_or(SyscallGroupName::Info, SyscallGroupName::from)
}

/// The opaque `field` that `recording.captured.read` takes. It names the call,
/// the event and the field, so a read needs no other state: `<stream>.<task>.
/// <call>.<event_seq>.<object_id>:<key>`.
pub fn field_id(call: CallRef, event_seq: u64, object_id: u32, key: &str) -> String {
    format!(
        "{}.{}.{}.{event_seq}.{object_id}:{key}",
        call.stream.0, call.task.0, call.call.0
    )
}

/// What a [`field_id`] names.
#[derive(Debug, PartialEq, Eq)]
pub struct FieldRef {
    /// `(stream, task, call)`.
    pub call: (u64, u64, u64),
    pub event_seq: u64,
    pub object_id: u32,
    pub key: String,
}

/// The inverse of [`field_id`].
pub fn parse_field_id(text: &str) -> Option<FieldRef> {
    let (ids, key) = text.split_once(':')?;
    let mut parts = ids.split('.');
    let mut number = || parts.next()?.parse::<u64>().ok();
    let (stream, task, call, seq, object) = (number()?, number()?, number()?, number()?, number()?);
    if parts.next().is_some() || key.is_empty() || key.len() > 256 {
        return None;
    }
    Some(FieldRef {
        call: (stream, task, call),
        event_seq: seq,
        object_id: u32::try_from(object).ok()?,
        key: key.to_owned(),
    })
}

pub fn captured_field(
    call: CallRef,
    event_seq: u64,
    field: &FieldSummary,
    scrub: &Scrub,
) -> CapturedField {
    CapturedField {
        field: field_id(call, event_seq, field.object_id, &field.key),
        key: field.key.clone(),
        arg: field.arg,
        layout: field.layout.clone(),
        logical_len: field.logical_len,
        captured_len: field.captured_len,
        status: field.status.map(|status| status.to_string()),
        capture_error: (field.capture_error != 0).then(|| field.capture_error.to_string()),
        complete: field.complete,
        preview: base64(&field.preview),
        ranges: field
            .ranges
            .iter()
            .map(|(offset, len)| [U64(*offset), U64(*len)])
            .collect(),
        recapture: field
            .recapture
            .as_ref()
            .map(|recapture| scrub.text(&format!("{recapture:?}"))),
    }
}

/// The number the guest used for a call. An event's id carries its ABI in the
/// high bits (arm64, arm and i386 calls), which a 32-bit number cannot hold:
/// the row's `name` says which table the number belongs to.
fn wire_nr(id: u64) -> u32 {
    u32::try_from(antinomie_monitor_core::syscalls::wire_number(id)).unwrap_or(u32::MAX)
}

pub fn call_event(
    call: CallRef,
    event: &EventSummary,
    ts_ms: impl Fn(u64) -> Option<u64>,
    scrub: &Scrub,
) -> CallEvent {
    CallEvent {
        event_seq: U64(event.event_seq),
        phase: event.phase,
        syscall_nr: wire_nr(event.syscall_nr),
        syscall_name: event.syscall_name.clone(),
        pid: event.pid,
        tid: event.tid,
        cpu: event.cpu,
        guest_ns: event.timestamp_ns,
        ts_ms: ts_ms(event.timestamp_ns),
        args: event
            .args
            .map(|args| args.iter().map(|a| hex(*a)).collect()),
        result: event.result.map(|r| r.to_string()),
        complete: event.complete,
        issues: event.issues.iter().map(|issue| scrub.text(issue)).collect(),
        fields: event
            .fields
            .iter()
            .map(|field| captured_field(call, event.event_seq, field, scrub))
            .collect(),
    }
}

/// A lossy text of an engine preview, at most 256 characters.
fn preview_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(256).collect()
}

pub fn trace_row(call: &InvocationSummary, ts_ms: impl Fn(u64) -> Option<u64>) -> Option<TraceRow> {
    let base = call.entry.as_ref().or(call.exit.as_ref())?;
    Some(TraceRow {
        call: call_ref(call),
        guest_ns: base.timestamp_ns,
        ts_ms: ts_ms(base.timestamp_ns),
        pid: base.pid,
        tid: base.tid,
        name: base.syscall_name.clone(),
        nr: wire_nr(base.syscall_nr),
        args: base.args.map(|args| args.iter().map(|a| hex(*a)).collect()),
        ret: call
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .map(|r| r.to_string()),
        complete: base.complete,
        group: group_of(&base.syscall_name),
        args_preview: base
            .fields
            .iter()
            .map(|field| ArgPreview {
                key: field.key.clone(),
                arg: field.arg,
                layout: field.layout.clone(),
                captured_len: field.captured_len,
                logical_len: field.logical_len,
                complete: field.complete,
                text: preview_text(&field.preview),
            })
            .collect(),
        async_saved: call.async_saved,
    })
}

fn wait_status(status: &WaitStatus) -> WaitStatusInfo {
    match status {
        WaitStatus::Exited { code } => WaitStatusInfo {
            raw: i32::from(*code) << 8,
            exited: true,
            code: Some(i32::from(*code)),
            signal: None,
            core_dumped: false,
        },
        WaitStatus::Signaled {
            signal,
            core_dumped,
        } => WaitStatusInfo {
            raw: i32::from(*signal) | if *core_dumped { 128 } else { 0 },
            exited: false,
            code: None,
            signal: Some(i32::from(*signal)),
            core_dumped: *core_dumped,
        },
    }
}

pub fn invocation(
    call: &InvocationSummary,
    ts_ms: impl Fn(u64) -> Option<u64> + Copy,
    scrub: &Scrub,
) -> Invocation {
    let id = call_ref(call);
    let event = |event: &EventSummary| call_event(id, event, ts_ms, scrub);
    Invocation {
        call: id,
        entry: call.entry.as_ref().map(event),
        exit: call.exit.as_ref().map(event),
        task_exit: call.task_exit.as_ref().map(event),
        async_events: call.async_events.iter().map(event).collect(),
        async_saved: call.async_saved,
        async_omitted: call.async_omitted(),
        kernel_notes: call.kernel_notes.iter().map(event).collect(),
        task_exit_status: call.task_exit_status().as_ref().map(wait_status),
    }
}

/// The event of `call` with `event_seq`, wherever it sits.
pub fn find_event(call: &InvocationSummary, event_seq: u64) -> Option<&EventSummary> {
    call.entry
        .iter()
        .chain(call.exit.iter())
        .chain(call.task_exit.iter())
        .chain(call.async_events.iter())
        .chain(call.kernel_notes.iter())
        .find(|event| event.event_seq == event_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn a_field_id_names_its_call_and_round_trips() {
        let call = CallRef {
            stream: U64(u64::MAX),
            task: U64(2),
            call: U64(3),
        };
        let id = field_id(call, 9, 7, "path");
        assert_eq!(
            parse_field_id(&id),
            Some(FieldRef {
                call: (u64::MAX, 2, 3),
                event_seq: 9,
                object_id: 7,
                key: "path".to_owned()
            })
        );
        for bad in [
            "",
            "7:path",
            "1.2.3.4:x",
            "1.2.3.4.5:",
            "1.2.3.4.5.6:x",
            "a.b.c.d.e:x",
        ] {
            assert_eq!(parse_field_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn registers_are_lower_case_hex() {
        assert_eq!(hex(255), "0xff");
        assert_eq!(hex(0), "0x0");
    }
}

#[cfg(test)]
mod wire_nr_tests {
    use super::wire_nr;
    use antinomie_monitor_core::syscalls::{self, Abi};

    /// An arm64 or compat call's id keeps its ABI in the high bits; the row
    /// shows the number the guest used (B11 of the Arm evaluation: every row
    /// read 4294967295).
    #[test]
    fn a_row_shows_the_guests_number_not_the_abi_tagged_id() {
        assert_eq!(wire_nr(59), 59);
        assert_eq!(wire_nr(syscalls::id(Abi::Aarch64, 221)), 221);
        assert_eq!(wire_nr(syscalls::id(Abi::Arm, 11)), 11);
        assert_eq!(wire_nr(syscalls::untabled_id(500)), 500);
    }
}
