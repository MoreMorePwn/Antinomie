// SPDX-License-Identifier: GPL-3.0-only
//! Builders for the calls the rule tests feed the engine.
pub(super) use super::super::super::tests::{call, captured, path_call};
pub(super) use super::super::super::{EventSummary, Finding, InvocationSummary};
use super::super::*;
pub(super) use super::super::{view_keeps, View};
use antinomie_monitor_core::kernel_notes::{
    CREDS_KEY, EXEC_IMAGE_KEY, FILE_ID_KEY, FILE_ID_LAYOUT,
};

pub(super) type Calls = Vec<InvocationSummary>;
const POINTER: &str = "linux-6.12.94/x86_64/pointer";
pub(super) const MS: u64 = 1_000_000;
pub(super) const SECOND: u64 = 1_000_000_000;

/// Number the calls in order, one millisecond apart, and run the engine over them.
pub(in crate::triage) fn run(calls: Calls) -> Output {
    run_with(
        calls,
        Options {
            show_info: true,
            capture_all: false,
        },
    )
}

pub(super) fn run_with(mut calls: Calls, options: Options) -> Output {
    for (at, row) in calls.iter_mut().enumerate() {
        let id = at as u64 + 1;
        row.call_id = id;
        for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
            event.call_id = id;
            if event.timestamp_ns == 0 || event.timestamp_ns == 1 {
                event.timestamp_ns = id * MS;
            }
        }
    }
    suspicious_output(&calls, options)
}

/// Move a call to a time, and everything after it by the same step.
pub(super) fn at(mut row: InvocationSummary, ns: u64) -> InvocationSummary {
    for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
        event.timestamp_ns = ns;
    }
    row
}

pub(super) fn text(row: &Finding, key: &str) -> String {
    row.values
        .iter()
        .find_map(|(name, value)| match (*name, value) {
            (name, RowValue::Text(text)) if name == key => Some(text.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

pub(super) fn list(row: &Finding, key: &str) -> Vec<String> {
    row.values
        .iter()
        .find_map(|(name, value)| match (*name, value) {
            (name, RowValue::List(list)) if name == key => Some(list.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

pub(super) fn rows<'a>(out: &'a Output, rule: &str) -> Vec<&'a Finding> {
    out.rows
        .iter()
        .filter(|row| text(row, "finding.rule") == rule)
        .collect()
}

pub(super) fn has(out: &Output, rule: &str) -> bool {
    !rows(out, rule).is_empty()
}

/// The tier of the only row of a rule, if there is one.
pub(super) fn tier(out: &Output, rule: &str) -> Option<String> {
    let found = rows(out, rule);
    assert!(found.len() <= 1, "{rule}: {} rows", found.len());
    found.first().map(|row| text(row, "finding.tier"))
}

pub(super) fn rules_of(out: &Output) -> Vec<String> {
    let mut rules: Vec<_> = out
        .rows
        .iter()
        .map(|row| text(row, "finding.rule"))
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

pub(super) fn count(row: &Finding) -> u64 {
    files::number(&row.values, "finding.count").unwrap_or(0)
}

pub(super) fn with_args(mut row: InvocationSummary, args: [u64; 6]) -> InvocationSummary {
    row.entry.as_mut().unwrap().args = Some(args);
    row
}

pub(super) fn with_path(mut row: InvocationSummary, key: &str, path: &str) -> InvocationSummary {
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured(key, "", &bytes));
    row
}

pub(super) fn with_entry(mut row: InvocationSummary, key: &str, data: &[u8]) -> InvocationSummary {
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured(key, "", data));
    row
}

pub(super) fn with_exit(mut row: InvocationSummary, key: &str, data: &[u8]) -> InvocationSummary {
    row.exit
        .as_mut()
        .unwrap()
        .fields
        .push(captured(key, "", data));
    row
}

pub(super) fn with_notes(
    mut row: InvocationSummary,
    notes: Vec<EventSummary>,
) -> InvocationSummary {
    row.kernel_notes = notes;
    row
}

fn strings(row: &mut InvocationSummary, argument: usize, items: &[&str]) {
    let entry = row.entry.as_mut().unwrap();
    for (index, item) in items.iter().enumerate() {
        let mut bytes = item.as_bytes().to_vec();
        bytes.push(0);
        entry.fields.push(captured(
            &format!("arg{argument}.ptr[{index}]"),
            POINTER,
            &(0x1000 + index as u64).to_le_bytes(),
        ));
        entry.fields.push(captured(
            &format!("arg{argument}.string[{index}]"),
            "",
            &bytes,
        ));
    }
    entry.fields.push(captured(
        &format!("arg{argument}.ptr[{}]", items.len()),
        POINTER,
        &0u64.to_le_bytes(),
    ));
}

/// An execve of `path` whose whole argument vector was captured.
pub(super) fn exec(pid: u32, path: &str, argv: &[&str]) -> InvocationSummary {
    exec_env(pid, path, argv, &[])
}

pub(super) fn exec_env(pid: u32, path: &str, argv: &[&str], envp: &[&str]) -> InvocationSummary {
    let mut row = path_call(pid, 59, "execve", 0, path);
    strings(&mut row, 1, argv);
    if !envp.is_empty() {
        strings(&mut row, 2, envp);
    }
    row
}

pub(super) fn failed_exec(pid: u32, path: &str, argv: &[&str]) -> InvocationSummary {
    let mut row = exec(pid, path, argv);
    row.exit.as_mut().unwrap().result = Some(-2);
    row
}

/// `sh -c SCRIPT`
pub(super) fn shell(pid: u32, script: &str) -> InvocationSummary {
    exec(pid, "/bin/sh", &["sh", "-c", script])
}

pub(super) fn open(pid: u32, path: &str, flags: u64, result: i64) -> InvocationSummary {
    with_args(
        path_call(pid, 2, "open", result, path),
        [0, flags, 0, 0, 0, 0],
    )
}

pub(super) fn open_read(pid: u32, path: &str, fd: i64) -> InvocationSummary {
    open(pid, path, 0, fd)
}

pub(super) fn open_write(pid: u32, path: &str, fd: i64) -> InvocationSummary {
    // O_WRONLY | O_CREAT | O_APPEND
    open(pid, path, 0o2101, fd)
}

pub(super) fn open_truncate(pid: u32, path: &str, fd: i64) -> InvocationSummary {
    // O_WRONLY | O_CREAT | O_TRUNC
    open(pid, path, 0o1101, fd)
}

pub(super) fn read(pid: u32, fd: u64, data: &[u8]) -> InvocationSummary {
    let row = with_args(
        call(pid, 0, "read", data.len() as i64),
        [fd, 0, 4096, 0, 0, 0],
    );
    with_exit(row, "arg1.data", data)
}

pub(super) fn write(pid: u32, fd: u64, data: &[u8]) -> InvocationSummary {
    let row = with_args(
        call(pid, 1, "write", data.len() as i64),
        [fd, 0, data.len() as u64, 0, 0, 0],
    );
    with_entry(row, "arg1.data", data)
}

pub(super) fn close(pid: u32, fd: u64) -> InvocationSummary {
    with_args(call(pid, 3, "close", 0), [fd, 0, 0, 0, 0, 0])
}

pub(super) fn sys(pid: u32, nr: u64, name: &str, args: [u64; 6], result: i64) -> InvocationSummary {
    with_args(call(pid, nr, name, result), args)
}

pub(super) fn unlink(pid: u32, path: &str) -> InvocationSummary {
    path_call(pid, 87, "unlink", 0, path)
}

pub(super) fn rename(pid: u32, old: &str, new: &str) -> InvocationSummary {
    let row = with_path(call(pid, 82, "rename", 0), "arg0.old_path", old);
    with_path(row, "arg1.new_path", new)
}

pub(super) fn chmod(pid: u32, path: &str, mode: u64) -> InvocationSummary {
    with_args(path_call(pid, 90, "chmod", 0, path), [0, mode, 0, 0, 0, 0])
}

pub(super) fn stat(pid: u32, path: &str, result: i64) -> InvocationSummary {
    path_call(pid, 4, "stat", result, path)
}

pub(super) fn address(family: u16, ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut data = family.to_le_bytes().to_vec();
    data.extend(port.to_be_bytes());
    data.extend(ip);
    data.extend([0; 8]);
    data
}

pub(super) fn socket(pid: u32, domain: u64, kind: u64, fd: i64) -> InvocationSummary {
    sys(pid, 41, "socket", [domain, kind, 0, 0, 0, 0], fd)
}

pub(super) fn connect(pid: u32, fd: u64, ip: [u8; 4], port: u16) -> InvocationSummary {
    let row = sys(pid, 42, "connect", [fd, 0, 16, 0, 0, 0], 0);
    with_entry(row, "arg1.address", &address(2, ip, port))
}

pub(super) fn dup2(pid: u32, old: u64, new: u64) -> InvocationSummary {
    sys(pid, 33, "dup2", [old, new, 0, 0, 0, 0], new as i64)
}

pub(super) fn mmap(pid: u32, prot: u64, flags: u64, result: i64) -> InvocationSummary {
    sys(pid, 9, "mmap", [0, 4096, prot, flags, u64::MAX, 0], result)
}

pub(super) fn fork(pid: u32, child: i64) -> InvocationSummary {
    call(pid, 57, "fork", child)
}

/// A credentials record: uid, euid, suid, fsuid, then the group ids.
pub(super) fn creds(ids: [u32; 8], caps: u64, reason: u32) -> EventSummary {
    let mut bytes: Vec<u8> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
    for value in [u32::MAX, u32::MAX, reason, 0] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(caps.to_le_bytes());
    bytes.extend(caps.to_le_bytes());
    bytes.extend([0; 8]);
    note(CREDS_KEY, "antinomie.creds/1", &bytes)
}

pub(super) const ROOT: [u32; 8] = [0; 8];
pub(super) const USER: [u32; 8] = [1000, 1000, 1000, 1000, 100, 100, 100, 100];

pub(super) fn file_id(kind: u8, ino: u64, nlink: u32) -> EventSummary {
    let mut bytes = vec![0u8; 32];
    bytes[0] = kind;
    bytes[1] = 2;
    bytes[4..8].copy_from_slice(&nlink.to_le_bytes());
    bytes[8..16].copy_from_slice(&0x803u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&ino.to_le_bytes());
    bytes[28..32].copy_from_slice(&0o100644u32.to_le_bytes());
    note(FILE_ID_KEY, FILE_ID_LAYOUT, &bytes)
}

pub(super) fn exec_image(interpreter: Option<&str>, path: &str) -> EventSummary {
    let mut bytes = vec![0u8; 40];
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    let mut interp = interpreter
        .map(|text| text.as_bytes().to_vec())
        .unwrap_or_default();
    if interpreter.is_some() {
        interp.push(0);
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
    }
    bytes[4..8].copy_from_slice(&(interp.len() as u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&(name.len() as u32).to_le_bytes());
    bytes.extend(interp);
    bytes.extend(name);
    note(EXEC_IMAGE_KEY, "antinomie.execimg/1", &bytes)
}

fn note(key: &str, layout: &str, bytes: &[u8]) -> EventSummary {
    let mut event = call(1, 0, "", 0).entry.unwrap();
    event.phase = 3;
    event.args = None;
    event.fields = vec![captured(key, layout, bytes)];
    event
}

/// Rows for tests of the views that show them: a task that reads two kinds of VM
/// evidence, so its anti-analysis row is MEDIUM.
pub(in crate::triage) fn evasion_rows() -> Vec<Finding> {
    let calls = vec![
        open_read(1, "/sys/class/dmi/id/sys_vendor", 3),
        read(1, 3, b"QEMU\n"),
        open_read(1, "/proc/cpuinfo", 4),
        read(1, 4, b"flags\t: fpu hypervisor\n"),
    ];
    run(calls).rows
}
