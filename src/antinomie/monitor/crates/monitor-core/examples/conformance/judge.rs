// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Judging one recorded run against its fixture's `ANT_EXPECT` lines: find the
//! invocation each line describes, then compare arguments, result, captured
//! data, capture statuses, file identity and async requests. Everything that
//! is wrong is a problem; a pointer argument the recorder has no decoder for
//! is a gap, reported separately so the coverage matrix can name it.
use crate::oracle::{DataItem, Expect, Transcript};
use antinomie_monitor_core::{
    EventSummary, FieldSummary, InvocationSummary, kernel_notes, recording, syscalls,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

/// `enum ant_status` names, index = status.
pub const STATUS_NAMES: [&str; 13] = [
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

pub fn status_name(field: &FieldSummary) -> String {
    match field.status {
        Some(status) => STATUS_NAMES
            .get(status as usize)
            .map_or_else(|| format!("STATUS_{status}"), |name| (*name).to_owned()),
        None => "MISSING_END".into(),
    }
}

pub type Key = (u64, u64, u64);

pub fn key(call: &InvocationSummary) -> Key {
    (call.stream_id, call.task_cookie, call.call_id)
}

/// A pointer argument the recorder could not decode, or captured nothing for
/// although the program passed data there.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Gap {
    pub nr: u64,
    /// "no_decoder", "not_captured" or "render".
    pub kind: String,
    /// The recorded key or `argN`, and what is missing.
    pub what: String,
}

/// The verdict of one `ANT_EXPECT` line.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CaseResult {
    pub label: String,
    pub seq: u64,
    pub nr: u64,
    pub name: String,
    pub matched: Option<Key>,
    pub args_ok: bool,
    pub ret_ok: bool,
    pub data_ok: bool,
    pub async_ok: Option<bool>,
    pub file_ok: Option<bool>,
    pub success: bool,
    /// Arguments the program described data for: the view must show it.
    pub data_args: Vec<u8>,
    /// The fixture's reason for the case's shape.
    pub why: Option<String>,
    pub problems: Vec<String>,
    pub gaps: Vec<Gap>,
}

/// Issues of one event the case's own fields explain: a field whose
/// non-complete status the case declared or accepts.
fn explained_issue(issue: &str, accounted: &[u32]) -> bool {
    issue
        .strip_prefix("object ")
        .and_then(|rest| rest.split_once(" capture incomplete, status "))
        .and_then(|(id, _)| id.parse::<u32>().ok())
        .is_some_and(|id| accounted.contains(&id))
}

/// Field data as captured: the covered prefix, read whole when it is longer
/// than the preview the summary carries.
pub fn field_bytes(run: &Path, field: &FieldSummary) -> Result<Vec<u8>, String> {
    // Captured chunks are separate ranges; the covered prefix runs while they
    // follow each other.
    let mut covered = 0u64;
    let mut ranges = field.ranges.clone();
    ranges.sort_unstable();
    for (offset, len) in ranges {
        if offset > covered {
            break;
        }
        covered = covered.max(offset.saturating_add(len));
    }
    if covered <= field.preview.len() as u64 {
        return Ok(field.preview[..covered as usize].to_vec());
    }
    let mut data = Vec::new();
    while (data.len() as u64) < covered {
        let len = (covered - data.len() as u64).min(65536) as usize;
        data.extend(
            recording::read_captured_range(run, field, data.len() as u64, len)
                .map_err(|e| format!("{}: {e}", field.key))?,
        );
    }
    Ok(data)
}

/// The argument a field belongs to: the descriptor's index, else its key.
pub fn field_arg(field: &FieldSummary) -> Option<u8> {
    field.arg.or_else(|| {
        let rest = field.key.strip_prefix("arg")?;
        let digit = *rest.as_bytes().first()?;
        ((b'0'..=b'5').contains(&digit)
            && rest
                .as_bytes()
                .get(1)
                .is_none_or(|b| matches!(b, b'.' | b'[')))
        .then_some(digit - b'0')
    })
}

fn hex(data: &[u8]) -> String {
    let mut text: String = data.iter().take(48).map(|b| format!("{b:02x}")).collect();
    if data.len() > 48 {
        text.push_str(&format!("…({} bytes)", data.len()));
    }
    text
}

/// Selector gaps record the program's own unknown command: that is a correct
/// decode of an invalid input, not a missing decoder.
fn selector_gap(field: &FieldSummary) -> bool {
    [".unknown_selector", ".unknown_option", ".unknown_rule"]
        .iter()
        .any(|suffix| field.key.ends_with(suffix))
}

/// Kernel-internal restart codes a call interrupted by a handled signal
/// returns at its exit; the program sees EINTR.
fn restart_code(result: i64) -> bool {
    matches!(result, -512 | -513 | -514 | -516)
}

pub struct Judge<'a> {
    pub run: &'a Path,
    pub calls: &'a [InvocationSummary],
    /// Calls by (tid, nr), in recording order.
    by_thread: HashMap<(u32, u64), Vec<usize>>,
    /// Async events by user_data, over all calls.
    by_user_data: HashMap<u64, Vec<(usize, &'a EventSummary)>>,
    used: Vec<bool>,
}

pub fn async_scalar(event: &EventSummary, key: &str) -> Option<u64> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    Some(u64::from_le_bytes(field.preview.get(..8)?.try_into().ok()?))
}

fn representative(call: &InvocationSummary) -> Option<&EventSummary> {
    call.entry
        .as_ref()
        .or(call.exit.as_ref())
        .or(call.task_exit.as_ref())
}

impl<'a> Judge<'a> {
    pub fn new(run: &'a Path, calls: &'a [InvocationSummary]) -> Self {
        let mut by_thread: HashMap<(u32, u64), Vec<usize>> = HashMap::new();
        let mut by_user_data: HashMap<u64, Vec<(usize, &EventSummary)>> = HashMap::new();
        for (index, call) in calls.iter().enumerate() {
            if let Some(event) = representative(call) {
                by_thread
                    .entry((event.tid, event.syscall_nr))
                    .or_default()
                    .push(index);
            }
            for event in &call.async_events {
                if let Some(user_data) = async_scalar(event, "async.user_data") {
                    by_user_data
                        .entry(user_data)
                        .or_default()
                        .push((index, event));
                }
            }
        }
        Self {
            run,
            calls,
            by_thread,
            by_user_data,
            used: vec![false; calls.len()],
        }
    }

    pub fn used(&self) -> &[bool] {
        &self.used
    }

    /// The unused call `expect` describes. Arguments must match unless
    /// `strict` is false (then the closest call in the window is returned so
    /// the mismatch can be shown).
    fn find(&self, expect: &Expect, args: Option<[u64; 6]>, strict: bool) -> Option<usize> {
        let candidates = self.by_thread.get(&(expect.tid, expect.nr))?;
        candidates.iter().copied().find(|&index| {
            if self.used[index] {
                return false;
            }
            let call = &self.calls[index];
            let within = |event: &Option<EventSummary>| {
                event
                    .as_ref()
                    .is_some_and(|e| (expect.t0..=expect.t1).contains(&e.timestamp_ns))
            };
            if expect.implicit {
                return within(&call.entry) || within(&call.exit);
            }
            if !within(&call.entry) {
                return false;
            }
            let ended = if expect.noreturn {
                call.task_exit.is_some()
            } else {
                call.exit
                    .as_ref()
                    .is_some_and(|e| e.timestamp_ns <= expect.t1)
            };
            if !ended {
                return false;
            }
            match (strict, args, call.entry.as_ref().and_then(|e| e.args)) {
                (true, Some(want), Some(got)) => {
                    (0..6).all(|i| expect.unchecked & (1 << i) != 0 || want[i] == got[i])
                }
                (true, _, _) => false,
                (false, ..) => true,
            }
        })
    }

    pub fn judge(&mut self, expect: &Expect) -> CaseResult {
        let mut result = CaseResult {
            label: expect.label.clone(),
            seq: expect.seq,
            nr: expect.nr,
            name: expect.name.clone(),
            matched: None,
            args_ok: true,
            ret_ok: true,
            data_ok: true,
            async_ok: None,
            file_ok: None,
            success: expect.ret.is_some_and(|ret| ret >= 0),
            data_args: Vec::new(),
            why: expect.why.clone(),
            problems: Vec::new(),
            gaps: Vec::new(),
        };
        if !expect.ok {
            result
                .problems
                .push("the fixture says the call did not do what the case meant".into());
        }
        if syscalls::syscall(expect.nr).map(|info| info.name.as_str()) != Some(&expect.name) {
            result.problems.push(format!(
                "the fixture calls {} number {}, the schema names it {}",
                expect.name,
                expect.nr,
                syscalls::name(expect.nr)
            ));
        }
        let args = if expect.implicit {
            None
        } else {
            match expect.args() {
                Ok(args) => Some(args),
                Err(error) => {
                    result.problems.push(error);
                    None
                }
            }
        };
        let index = match self.find(expect, args, !expect.implicit) {
            Some(index) => Some(index),
            None if !expect.implicit => {
                let loose = self.find(expect, args, false);
                if let Some(index) = loose {
                    result.args_ok = false;
                    let got = self.calls[index].entry.as_ref().and_then(|e| e.args);
                    result.problems.push(format!(
                        "arguments differ: recorded {:x?}, the program passed {:x?}",
                        got.unwrap_or_default(),
                        args.unwrap_or_default()
                    ));
                }
                loose
            }
            None => None,
        };
        let Some(index) = index else {
            result.args_ok = false;
            result.ret_ok = false;
            result.data_ok = false;
            result.problems.push(format!(
                "no recorded {} call of thread {} between {} and {} ns",
                expect.name, expect.tid, expect.t0, expect.t1
            ));
            return result;
        };
        self.used[index] = true;
        let call = &self.calls[index];
        result.matched = Some(key(call));
        self.check_result(expect, call, &mut result);
        if !expect.implicit {
            self.check_fields(expect, call, &mut result);
        }
        if let Some(file) = &expect.file {
            let found = call.kernel_notes.iter().find_map(kernel_notes::file_id);
            let ok = match &found {
                Some(id) => {
                    let kind = format!("{:?}", id.kind).to_uppercase();
                    // The program saw the links before the call; an unlink
                    // leaves one less, a directory removal none.
                    let nlink_ok = u64::from(id.nlink) == file.nlink
                        || (file.kind == "UNLINK"
                            && (u64::from(id.nlink) + 1 == file.nlink
                                || (id.directory && id.nlink == 0)));
                    let ok = kind == file.kind
                        && id.key.dev == file.dev()
                        && id.key.ino == file.ino
                        && nlink_ok;
                    if !ok {
                        result.problems.push(format!(
                            "file identity {kind} dev {:#x} ino {} nlink {}, the program saw {} dev {:#x} ino {} nlink {}",
                            id.key.dev, id.key.ino, id.nlink, file.kind, file.dev(), file.ino, file.nlink
                        ));
                    }
                    ok
                }
                None => {
                    result
                        .problems
                        .push(format!("no lifecycle.file_id record ({})", file.kind));
                    false
                }
            };
            result.file_ok = Some(ok);
        }
        if !expect.requests.is_empty() {
            let ok = self.check_async(expect, index, &mut result);
            result.async_ok = Some(ok);
        }
        result
    }

    fn check_result(&self, expect: &Expect, call: &InvocationSummary, result: &mut CaseResult) {
        if expect.noreturn {
            let status = call.task_exit.as_ref().and_then(|end| {
                end.fields
                    .iter()
                    .find(|field| field.key == "lifecycle.task_exit")
                    .and_then(|field| field.preview.get(..8))
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])))
            });
            if call.exit.is_some() {
                result.ret_ok = false;
                result
                    .problems
                    .push("a call that never returns has an Exit record".into());
            }
            if let Some(want) = expect.wait_status
                && status != Some(want as u32 as u64)
            {
                result.ret_ok = false;
                result.problems.push(format!(
                    "task exit status {status:?}, the parent saw {want:#x}"
                ));
            }
            return;
        }
        let recorded = call.exit.as_ref().and_then(|exit| exit.result);
        let ok = match (recorded, expect.ret) {
            (Some(got), Some(want)) => {
                got == want
                    || (restart_code(got) && (want == -4 || self.restarted(expect, call, got)))
            }
            (None, None) => true,
            _ => false,
        };
        if !ok {
            result.ret_ok = false;
            result.problems.push(format!(
                "result {recorded:?}, the program got {:?}",
                expect.ret
            ));
        }
    }

    /// Whether the kernel transparently restarted `call`: a later call of the
    /// same thread in the case's window continues it (restart_syscall after
    /// ERESTART_RESTARTBLOCK, the same call after the other restart codes).
    fn restarted(&self, expect: &Expect, call: &InvocationSummary, code: i64) -> bool {
        let Some(ended) = call.exit.as_ref().map(|exit| exit.timestamp_ns) else {
            return false;
        };
        let nr = if code == -516 { 219 } else { expect.nr };
        self.by_thread
            .get(&(expect.tid, nr))
            .into_iter()
            .flatten()
            .any(|&index| {
                self.calls[index]
                    .entry
                    .as_ref()
                    .is_some_and(|entry| (ended..=expect.t1).contains(&entry.timestamp_ns))
            })
    }

    fn check_fields(&self, expect: &Expect, call: &InvocationSummary, result: &mut CaseResult) {
        let phases: [(&str, Option<&EventSummary>); 2] =
            [("in", call.entry.as_ref()), ("out", call.exit.as_ref())];
        // Fields whose non-complete status the case accounts for.
        let mut accounted: BTreeMap<(&str, u32), String> = BTreeMap::new();
        for (phase, event) in phases {
            let Some(event) = event else { continue };
            for field in &event.fields {
                let status = status_name(field);
                if status == "COMPLETE" {
                    continue;
                }
                let arg = field_arg(field);
                let declared = expect.status.iter().any(|item| {
                    item.status == status
                        && (item.p == "any" || item.p == phase)
                        && match &item.key {
                            Some(key) => *key == field.key,
                            None => item.arg < 0 || arg == Some(item.arg as u8),
                        }
                });
                let allowed = expect
                    .allow
                    .as_ref()
                    .is_some_and(|allow| allow.status == status);
                if field.complete {
                    // Nothing to copy by contract (a NULL pointer, memory of
                    // another address space, memory the kernel uses later).
                    continue;
                }
                // A declared NO_DECODER on a call the kernel refused is the
                // program's invalid request (an unknown operation or flag),
                // decoded as such; on a call that succeeded it is a gap.
                let refused = declared && expect.ret.is_some_and(|ret| ret < 0);
                if status == "NO_DECODER" && !selector_gap(field) && !refused {
                    result.gaps.push(Gap {
                        nr: expect.nr,
                        kind: "no_decoder".into(),
                        what: field.key.clone(),
                    });
                    accounted.insert((phase, field.object_id), status);
                } else if declared || allowed {
                    accounted.insert((phase, field.object_id), status);
                } else {
                    result.data_ok = false;
                    result.problems.push(format!(
                        "{phase} field {} recorded {status} (error {})",
                        field.key, field.capture_error
                    ));
                }
            }
        }
        for item in &expect.status {
            let seen = phases.iter().any(|(phase, event)| {
                (item.p == "any" || item.p == *phase)
                    && event.is_some_and(|event| {
                        event.fields.iter().any(|field| {
                            status_name(field) == item.status
                                && match &item.key {
                                    Some(key) => *key == field.key,
                                    None => {
                                        item.arg < 0 || field_arg(field) == Some(item.arg as u8)
                                    }
                                }
                        })
                    })
            });
            if !seen {
                result.data_ok = false;
                result.problems.push(format!(
                    "expected status {} for {} ({}) not recorded",
                    item.status,
                    item.key
                        .clone()
                        .unwrap_or_else(|| format!("arg{}", item.arg)),
                    item.p
                ));
            }
        }
        for item in &expect.data {
            self.check_data(expect, &phases, item, result);
        }
        check_recaptures(expect, call, result);
        for (phase, event) in phases {
            let Some(event) = event else { continue };
            let ids: Vec<u32> = accounted
                .keys()
                .filter(|(p, _)| *p == phase)
                .map(|(_, id)| *id)
                .collect();
            for issue in &event.issues {
                if !explained_issue(issue, &ids) {
                    result.problems.push(format!("{phase} issue: {issue}"));
                }
            }
        }
        if call.entry.is_none() {
            result.problems.push("missing Entry".into());
        }
    }

    fn check_data(
        &self,
        expect: &Expect,
        phases: &[(&str, Option<&EventSummary>); 2],
        item: &DataItem,
        result: &mut CaseResult,
    ) {
        let wanted = match item.bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                result.problems.push(format!("oracle data: {error}"));
                return;
            }
        };
        let fields: Vec<&FieldSummary> = phases
            .iter()
            .filter(|(phase, _)| item.p == "any" || item.p == *phase)
            .filter_map(|(_, event)| *event)
            .flat_map(|event| event.fields.iter())
            .filter(|field| match &item.key {
                Some(key) => field.key == *key,
                None => item.arg.is_some() && field_arg(field) == item.arg,
            })
            .collect();
        let what = item
            .key
            .clone()
            .unwrap_or_else(|| format!("arg{}", item.arg.unwrap_or(255)));
        if fields.is_empty() {
            result.gaps.push(Gap {
                nr: expect.nr,
                kind: "not_captured".into(),
                what: format!("{} {what}", item.p),
            });
            return;
        }
        let mut seen = Vec::new();
        for field in &fields {
            if field.status != Some(0) {
                seen.push(format!("{} {}", field.key, status_name(field)));
                continue;
            }
            let data = match field_bytes(self.run, field) {
                Ok(data) => data,
                Err(error) => {
                    seen.push(error);
                    continue;
                }
            };
            let complete = field.complete;
            let matches = match item.kind.as_str() {
                "any" => complete,
                "str" => {
                    let end = data
                        .iter()
                        .rposition(|b| *b != 0)
                        .map_or(0, |last| last + 1);
                    complete && data[..end] == wanted[..]
                }
                _ => complete && data == wanted,
            };
            if matches {
                // The view must show this argument's data, whichever key holds
                // it; an empty object leaves only the address to show.
                if let Some(arg) = field_arg(field).filter(|_| !data.is_empty())
                    && !result.data_args.contains(&arg)
                {
                    result.data_args.push(arg);
                    result.data_args.sort_unstable();
                }
                return;
            }
            seen.push(format!(
                "{} = {}{}",
                field.key,
                hex(&data),
                if complete { "" } else { " (incomplete)" }
            ));
        }
        result.data_ok = false;
        result.problems.push(format!(
            "{} {what}: the program {} {}, recorded {}",
            item.p,
            if item.p == "out" {
                "read back"
            } else {
                "passed"
            },
            if item.kind == "any" {
                "data".into()
            } else {
                hex(&wanted)
            },
            seen.join("; ")
        ));
    }

    fn check_async(&self, expect: &Expect, index: usize, result: &mut CaseResult) -> bool {
        let mut ok = true;
        for item in &expect.requests {
            let user_data = match item.user_data() {
                Ok(value) => value,
                Err(error) => {
                    result.problems.push(error);
                    ok = false;
                    continue;
                }
            };
            let events = self
                .by_user_data
                .get(&user_data)
                .cloned()
                .unwrap_or_default();
            if events.is_empty() {
                result
                    .problems
                    .push(format!("no async record of request {user_data:#x}"));
                ok = false;
                continue;
            }
            if let (Some(key), Some(hex_data)) = (&item.key, &item.hex) {
                let wanted = crate::oracle::unhex(hex_data).unwrap_or_default();
                let found = events.iter().any(|(_, event)| {
                    event.fields.iter().any(|field| {
                        field.key == *key
                            && field.complete
                            && field_bytes(self.run, field).is_ok_and(|data| data == wanted)
                    })
                });
                if !found {
                    result.problems.push(format!(
                        "request {user_data:#x}: {key} not recorded as {}",
                        hex(&wanted)
                    ));
                    ok = false;
                }
                continue;
            }
            let stages: Vec<u64> = events
                .iter()
                .filter_map(|(_, event)| async_scalar(event, "async.stage"))
                .collect();
            if !stages.contains(&1) {
                result
                    .problems
                    .push(format!("request {user_data:#x}: no submission record"));
                ok = false;
            }
            if !events.iter().any(|(owner, _)| *owner == index) {
                result.problems.push(format!(
                    "request {user_data:#x}: recorded under another call than the one that submitted it"
                ));
                ok = false;
            }
            if let Some(op) = item.op
                && !events
                    .iter()
                    .any(|(_, event)| async_scalar(event, "async.opcode") == Some(op as u64))
            {
                result
                    .problems
                    .push(format!("request {user_data:#x}: opcode {op} not recorded"));
                ok = false;
            }
            if let Some(res) = item.res {
                let finals: Vec<i64> = events
                    .iter()
                    .filter(|(_, event)| matches!(async_scalar(event, "async.stage"), Some(3..=5)))
                    .filter_map(|(_, event)| async_scalar(event, "async.result"))
                    .map(|value| value as i64)
                    .collect();
                if !finals.contains(&res) {
                    result.problems.push(format!(
                        "request {user_data:#x}: completion results {finals:?}, the program got {res}"
                    ));
                    ok = false;
                }
            }
            for (_, event) in &events {
                for field in &event.fields {
                    let status = status_name(field);
                    if !field.complete && !expect.status.iter().any(|item| item.status == status) {
                        result.problems.push(format!(
                            "request {user_data:#x}: {} recorded {status}",
                            field.key
                        ));
                        ok = false;
                    }
                }
            }
        }
        ok
    }
}

/// Whether a call's phases disagree on which system call it is.
pub fn name_mismatch(call: &InvocationSummary) -> bool {
    let numbers: Vec<u64> = call
        .entry
        .iter()
        .chain(call.exit.iter())
        .map(|event| event.syscall_nr)
        .collect();
    numbers.windows(2).any(|pair| pair[0] != pair[1])
}

/// What the transcript says about the fixture itself.
pub fn transcript_problems(transcript: &Transcript) -> Vec<String> {
    let mut problems: Vec<String> = transcript
        .fixture_failures
        .iter()
        .map(|failure| format!("fixture failure: {failure}"))
        .collect();
    problems.extend(
        transcript
            .malformed
            .iter()
            .map(|line| format!("malformed oracle line: {line}")),
    );
    match &transcript.done {
        Some(done) if done["failures"].as_u64() == Some(0) => {}
        Some(done) => problems.push(format!("fixture ended with {done}")),
        None => problems.push("fixture never printed ANT_DONE".into()),
    }
    let mut labels = std::collections::HashSet::new();
    for expect in &transcript.expects {
        if !labels.insert((expect.label.as_str(), expect.pid)) {
            problems.push(format!("duplicate case label {}", expect.label));
        }
    }
    problems
}

/// Inputs captured after the Entry (contract section 22) are exactly the ones
/// the case declares, with the declared mark. A declared key ending in `*`
/// covers every key it starts with (an exec vector read on at exit).
fn check_recaptures(expect: &Expect, call: &InvocationSummary, result: &mut CaseResult) {
    let covers = |pattern: &str, key: &str| match pattern.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => pattern == key,
    };
    let fields = call
        .entry
        .iter()
        .chain(&call.exit)
        .flat_map(|event| &event.fields);
    let marked: Vec<(&str, &str)> = fields
        .filter_map(|field| Some((field.key.as_str(), field.recapture?.label())))
        .collect();
    for (key, mark) in &marked {
        if !expect
            .recapture
            .iter()
            .any(|item| covers(&item.key, key) && item.mark == *mark)
        {
            result.data_ok = false;
            result.problems.push(format!(
                "field {key} captured {mark}, which the case does not declare"
            ));
        }
    }
    for item in &expect.recapture {
        if !marked
            .iter()
            .any(|(key, mark)| covers(&item.key, key) && item.mark == *mark)
        {
            result.data_ok = false;
            result.problems.push(format!(
                "expected {} captured {}, not recorded",
                item.key, item.mark
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, arg: Option<u8>, status: u32, data: &[u8]) -> FieldSummary {
        FieldSummary {
            arg,
            object_id: 1,
            key: key.into(),
            layout: String::new(),
            logical_len: Some(data.len() as u64),
            captured_len: data.len() as u64,
            status: Some(status),
            capture_error: 0,
            complete: status == 0,
            preview: data.to_vec(),
            raw_path: None,
            ranges: vec![(0, data.len() as u64)],
            recapture: None,
        }
    }

    fn event(phase: u8, ts: u64, fields: Vec<FieldSummary>, result: Option<i64>) -> EventSummary {
        EventSummary {
            root_task_cookie: 1,
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            event_seq: u64::from(phase),
            phase,
            syscall_nr: 257,
            syscall_name: "openat".into(),
            pid: 10,
            tid: 10,
            cpu: 0,
            timestamp_ns: ts,
            args: Some([0xffff_ffff_ffff_ff9c, 0x1000, 0, 0, 0, 0]),
            result,
            complete: fields.iter().all(|f| f.complete),
            issues: Vec::new(),
            fields,
        }
    }

    fn call(entry_fields: Vec<FieldSummary>, result: i64) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            entry: Some(event(1, 100, entry_fields, None)),
            exit: Some(event(2, 110, Vec::new(), Some(result))),
            async_events: Vec::new(),
            async_saved: 0,
            task_exit: None,
            kernel_notes: Vec::new(),
        }
    }

    fn expect(extra: &str) -> Expect {
        serde_json::from_str(&format!(
            "{{\"seq\":1,\"label\":\"openat.x\",\"nr\":257,\"name\":\"openat\",\"pid\":10,\
             \"tid\":10,\"t0\":90,\"t1\":120,\"argc\":4,\"args\":[\"0xffffffffffffff9c\",\
             \"0x1000\",\"0\",\"0\",\"0\",\"0\"],\"ret\":3,\"ok\":true{extra}}}"
        ))
        .unwrap()
    }

    #[test]
    fn matching_call_with_its_path_passes() {
        let calls = [call(vec![field("arg1.path", Some(1), 0, b"io\0")], 3)];
        let mut judge = Judge::new(Path::new("."), &calls);
        let result = judge.judge(&expect(
            ",\"data\":[{\"p\":\"in\",\"arg\":1,\"kind\":\"str\",\"hex\":\"696f\"}]",
        ));
        assert!(result.problems.is_empty(), "{:?}", result.problems);
        assert!(result.gaps.is_empty());
        assert_eq!(result.matched, Some((1, 2, 3)));
    }

    #[test]
    fn wrong_bytes_result_and_arguments_are_problems() {
        let calls = [call(vec![field("arg1.path", Some(1), 0, b"ix\0")], 4)];
        let mut judge = Judge::new(Path::new("."), &calls);
        let mut wanted =
            expect(",\"data\":[{\"p\":\"in\",\"arg\":1,\"kind\":\"str\",\"hex\":\"696f\"}]");
        wanted.args[1] = "0x2000".into();
        let result = judge.judge(&wanted);
        assert!(!result.args_ok && !result.ret_ok && !result.data_ok);
        assert_eq!(result.problems.len(), 3, "{:?}", result.problems);
    }

    #[test]
    fn undeclared_status_fails_declared_passes_and_no_decoder_is_a_gap() {
        let calls = [call(vec![field("arg1.path", Some(1), 1, b"")], 3)];
        let result = Judge::new(Path::new("."), &calls).judge(&expect(""));
        assert!(!result.data_ok);
        let declared = Judge::new(Path::new("."), &calls).judge(&expect(
            ",\"status\":[{\"arg\":1,\"p\":\"in\",\"status\":\"COPY_FAULT\"}]",
        ));
        assert!(declared.problems.is_empty(), "{:?}", declared.problems);
        let missing = Judge::new(Path::new("."), &[call(Vec::new(), 3)]).judge(&expect(
            ",\"status\":[{\"arg\":1,\"p\":\"in\",\"status\":\"COPY_FAULT\"}]",
        ));
        assert!(!missing.data_ok);
        let gap = [call(vec![field("arg1.buf", Some(1), 4, b"")], 3)];
        let result = Judge::new(Path::new("."), &gap).judge(&expect(""));
        assert!(result.problems.is_empty(), "{:?}", result.problems);
        assert_eq!(result.gaps[0].kind, "no_decoder");
        let selector = [call(vec![field("fcntl.unknown_selector", None, 4, b"")], 3)];
        let result = Judge::new(Path::new("."), &selector).judge(&expect(""));
        assert!(!result.problems.is_empty() && result.gaps.is_empty());
    }

    #[test]
    fn data_for_an_argument_without_any_field_is_a_not_captured_gap() {
        let calls = [call(Vec::new(), 3)];
        let result = Judge::new(Path::new("."), &calls).judge(&expect(
            ",\"data\":[{\"p\":\"in\",\"arg\":2,\"kind\":\"buf\",\"hex\":\"00\"}]",
        ));
        assert!(result.problems.is_empty());
        assert_eq!(result.gaps[0].kind, "not_captured");
    }

    #[test]
    fn one_call_cannot_satisfy_two_cases_and_time_must_fit() {
        let calls = [call(Vec::new(), 3)];
        let mut judge = Judge::new(Path::new("."), &calls);
        assert!(judge.judge(&expect("")).problems.is_empty());
        assert!(!judge.judge(&expect("")).problems.is_empty());
        let mut late = expect("");
        late.t0 = 105;
        assert!(
            Judge::new(Path::new("."), &calls)
                .judge(&late)
                .matched
                .is_none()
        );
    }

    #[test]
    fn interrupted_calls_may_record_the_kernel_restart_code() {
        let calls = [call(Vec::new(), -514)];
        let mut wanted = expect("");
        wanted.ret = Some(-4);
        assert!(Judge::new(Path::new("."), &calls).judge(&wanted).ret_ok);
    }
}
