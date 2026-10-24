// SPDX-License-Identifier: GPL-3.0-only
//! Programs attached by a link, a raw tracepoint or a perf event, from load to attach.
use super::support::*;
use crate::triage::rules::Output;
use crate::triage::{bpf_notes, BpfNote, TriageInput};

const BPF: u64 = 321;
const IOCTL: u64 = 16;
const PERF_OPEN: u64 = 298;
const SET_BPF: u64 = 0x4004_2408;
const ATTR: &str = "linux-6.12.94/x86_64/bpf_attr";

fn put(attr: &mut [u8], at: usize, value: u64, width: usize) {
    attr[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn load(fd: i64) -> InvocationSummary {
    sys(1, BPF, "bpf", [5, 0, 152, 0, 0, 0], fd)
}

fn attr_call(command: u64, attr: &[u8], result: i64) -> InvocationSummary {
    let mut row = sys(1, BPF, "bpf", [command, 0, 152, 0, 0, 0], result);
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.attr", ATTR, attr));
    row
}

fn link(prog: u64, target: u64, kind: u64, result: i64) -> InvocationSummary {
    let mut attr = vec![0u8; 152];
    put(&mut attr, 0, prog, 4);
    put(&mut attr, 4, target, 4);
    put(&mut attr, 8, kind, 4);
    attr_call(28, &attr, result)
}

fn kprobe_multi(prog: u64, symbols: &[&str], result: i64) -> InvocationSummary {
    let mut attr = vec![0u8; 152];
    put(&mut attr, 0, prog, 4);
    put(&mut attr, 8, 42, 4);
    put(&mut attr, 20, symbols.len() as u64, 4);
    let mut row = attr_call(28, &attr, result);
    for (index, symbol) in symbols.iter().enumerate() {
        let mut bytes = symbol.as_bytes().to_vec();
        bytes.push(0);
        row.entry.as_mut().unwrap().fields.push(captured(
            &format!("arg1.attr.syms[{index}]"),
            "",
            &bytes,
        ));
    }
    row
}

fn raw_tracepoint(prog: u64, name: Option<&str>, result: i64) -> InvocationSummary {
    let mut attr = vec![0u8; 152];
    put(
        &mut attr,
        0,
        if name.is_some() { 0x7000_1000 } else { 0 },
        8,
    );
    put(&mut attr, 8, prog, 4);
    let mut row = attr_call(17, &attr, result);
    if let Some(name) = name {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        row.entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.attr.name", "", &bytes));
    }
    row
}

fn perf_open(kind: u32, config: u64, result: i64) -> InvocationSummary {
    let mut attr = vec![0u8; 136];
    put(&mut attr, 0, u64::from(kind), 4);
    put(&mut attr, 4, 136, 4);
    put(&mut attr, 8, config, 8);
    let mut row = sys(
        1,
        PERF_OPEN,
        "perf_event_open",
        [0, 0, 0, 0xffff_ffff, 0, 0],
        result,
    );
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.perf_event_attr", "", &attr));
    row
}

fn set_bpf(perf_fd: u64, prog: u64, result: i64) -> InvocationSummary {
    sys(1, IOCTL, "ioctl", [perf_fd, SET_BPF, prog, 0, 0, 0], result)
}

fn notes_of(mut calls: Calls) -> Vec<BpfNote> {
    for (at, row) in calls.iter_mut().enumerate() {
        for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
            event.call_id = at as u64 + 1;
        }
        row.call_id = at as u64 + 1;
    }
    bpf_notes(&TriageInput::page(&calls))
}

fn finding(out: &Output) -> &Finding {
    let found: Vec<_> = rows(out, "bpf.program")
        .into_iter()
        .filter(|row| text(row, "finding.object") != "BPF_PROG_LOAD")
        .collect();
    assert_eq!(found.len(), 1, "{:?}", rules_of(out));
    found[0]
}

#[test]
fn a_kprobe_multi_link_of_a_loaded_program_is_high_and_tied_to_the_load() {
    let calls = vec![
        load(3),
        kprobe_multi(3, &["do_sys_openat2", "tcp_connect"], 4),
    ];
    let notes = notes_of(calls.clone());
    assert_eq!(notes.len(), 2);
    assert!(notes[0]
        .lifecycle
        .as_deref()
        .unwrap()
        .contains("loaded program fd 3"));
    let attach = notes[1].lifecycle.as_deref().unwrap();
    assert_eq!(
        attach,
        "attached kprobe_multi of program fd 3 (loaded in call 1): 2 kernel symbols: do_sys_openat2, tcp_connect"
    );
    assert_eq!(notes[1].loaded_by, Some(1));
    assert!(notes[1].heading.contains("BPF_LINK_CREATE"));
    assert!(notes[1]
        .summary
        .starts_with("Attached kprobe_multi of program fd 3"));
    // Rows without an instruction image still select apart.
    assert_ne!(notes[0].identity.event_id, notes[1].identity.event_id);

    let out = run(calls);
    let row = finding(&out);
    assert_eq!(text(row, "finding.tier"), "high");
    assert_eq!(list(row, "finding.technique"), ["T1014", "DET0377"]);
    assert!(text(row, "finding.summary").contains("loaded in call 1"));
    assert!(list(row, "finding.detail")
        .iter()
        .any(|line| line.contains("do_sys_openat2")));
}

#[test]
fn link_tiers_follow_the_attach_type() {
    let tier_of = |kind: u64| {
        let out = run(vec![load(3), link(3, 5, kind, 4)]);
        text(finding(&out), "finding.tier")
    };
    assert_eq!(tier_of(24), "high", "fentry");
    assert_eq!(tier_of(25), "high", "fexit");
    assert_eq!(tier_of(27), "high", "lsm");
    assert_eq!(tier_of(0), "medium", "cgroup ingress");
    assert_eq!(tier_of(37), "medium", "xdp");
    assert_eq!(tier_of(45), "medium", "netfilter");
    let notes = notes_of(vec![link(9, 5, 24, 4)]);
    let line = notes[0].lifecycle.as_deref().unwrap();
    assert!(line.contains("its load was not seen"), "{line}");
    assert!(line.contains("name not captured"), "{line}");
    let xdp = notes_of(vec![link(9, 2, 37, 4)]);
    assert!(xdp[0]
        .lifecycle
        .as_deref()
        .unwrap()
        .contains("interface index 2"));
    let cgroup = notes_of(vec![link(9, 6, 0, 4)]);
    assert!(cgroup[0]
        .lifecycle
        .as_deref()
        .unwrap()
        .contains("cgroup fd 6"));
}

#[test]
fn a_failed_link_is_info() {
    let calls = vec![load(3), kprobe_multi(3, &["vfs_read"], -1)];
    let notes = notes_of(calls.clone());
    assert_eq!(
        notes[1].lifecycle.as_deref().unwrap(),
        "attach of kprobe_multi failed (-1) of program fd 3 (loaded in call 1): 1 kernel symbols: vfs_read"
    );
    let out = run(calls);
    assert_eq!(text(finding(&out), "finding.tier"), "info");
}

#[test]
fn a_raw_tracepoint_is_high_with_its_name() {
    let calls = vec![load(3), raw_tracepoint(3, Some("sys_enter"), 5)];
    let notes = notes_of(calls.clone());
    assert_eq!(
        notes[1].lifecycle.as_deref().unwrap(),
        "attached raw tracepoint of program fd 3 (loaded in call 1): tracepoint sys_enter"
    );
    let out = run(calls);
    let row = finding(&out);
    assert_eq!(text(row, "finding.tier"), "high");
    assert_eq!(list(row, "finding.technique"), ["T1014", "DET0377"]);

    let nameless = notes_of(vec![raw_tracepoint(4, None, 5)]);
    let line = nameless[0].lifecycle.as_deref().unwrap();
    assert!(line.contains("chosen at load, not captured"), "{line}");
    let denied = run(vec![raw_tracepoint(3, Some("sys_enter"), -1)]);
    assert_eq!(text(finding(&denied), "finding.tier"), "info");
    let unnamed = notes_of(vec![attr_call(17, &[0xff; 8], 5)]);
    assert!(unnamed[0]
        .lifecycle
        .as_deref()
        .unwrap()
        .contains("target not captured"));
}

#[test]
fn a_program_set_on_a_perf_event_is_tied_to_the_event_and_the_load() {
    let calls = vec![load(3), perf_open(2, 77, 4), set_bpf(4, 3, 0)];
    let notes = notes_of(calls.clone());
    assert_eq!(notes.len(), 3);
    assert!(notes[1].heading.contains("PERF_EVENT_OPEN"));
    assert_eq!(
        notes[1].lifecycle.as_deref().unwrap(),
        "perf event fd 4 opened: tracepoint id 77 (name not resolved)"
    );
    assert_eq!(
        notes[2].lifecycle.as_deref().unwrap(),
        "attached perf event of program fd 3 (loaded in call 1): perf event fd 4 opened in call 2: tracepoint id 77 (name not resolved)"
    );
    assert_eq!(notes[2].loaded_by, Some(1));
    let out = run(calls);
    let row = finding(&out);
    assert_eq!(text(row, "finding.tier"), "high");
    assert_eq!(list(row, "finding.technique"), ["T1014", "DET0377"]);

    let dynamic = run(vec![load(3), perf_open(7, 0, 4), set_bpf(4, 3, 0)]);
    assert_eq!(text(finding(&dynamic), "finding.tier"), "high");
    let software = run(vec![load(3), perf_open(1, 10, 4), set_bpf(4, 3, 0)]);
    assert_eq!(text(finding(&software), "finding.tier"), "medium");
    let failed = run(vec![load(3), perf_open(2, 77, 4), set_bpf(4, 3, -22)]);
    assert_eq!(text(finding(&failed), "finding.tier"), "info");
    let unseen = notes_of(vec![set_bpf(9, 3, 0)]);
    let line = unseen[0].lifecycle.as_deref().unwrap();
    assert!(
        line.contains("perf_event_open was not seen; target not captured"),
        "{line}"
    );
    let other_ioctl = run(vec![sys(1, IOCTL, "ioctl", [4, 0x2400, 0, 0, 0, 0], 0)]);
    assert!(!has(&other_ioctl, "bpf.program"));
}

#[test]
fn a_closed_program_fd_is_no_longer_tied() {
    let notes = notes_of(vec![
        load(3),
        sys(1, 3, "close", [3, 0, 0, 0, 0, 0], 0),
        link(3, 5, 24, 4),
    ]);
    assert_eq!(notes[1].loaded_by, None);
}
