// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The reduced recording keeps and drops calls by their own ABI's table
//! (ANT-T0438): x86-64 as before, AArch64, AArch32 and ia32 by their names.
use super::*;
use crate::syscalls::{Abi, table};

fn list() -> Vec<String> {
    ["execve", "openat", "mmap"].map(String::from).to_vec()
}

fn header(abi: u16, nr: u64, phase: u8) -> Header {
    Header {
        root_task_cookie: 1,
        capture_cookie: 1,
        record_type: 1,
        flags: 0,
        schema_id: 1,
        stream_id: 1,
        task_cookie: 1,
        call_id: 1,
        event_seq: 1,
        packet_seq: 1,
        timestamp_ns: 1,
        pid: 1,
        tid: 1,
        cpu: 0,
        syscall_nr: nr,
        abi,
        phase,
        fragment: 1,
        object_id: 0,
        object_offset: 0,
        object_total: 0,
    }
}

/// The verdict of the call `name` as an `abi` program's entry packet.
fn verdict(native: Abi, record_abi: u16, table_abi: Abi, name: &str) -> Verdict {
    let number = table(table_abi).number(name).expect(name);
    Reducer::new(&list()).verdict(&header(record_abi, number, 1), native)
}

#[test]
fn x86_64_decisions_are_the_old_ones() {
    let reducer = Reducer::new(&list());
    let old: HashSet<u64> = list()
        .iter()
        .filter_map(|name| crate::syscalls::number(name))
        .collect();
    for entry in table(Abi::X86_64).all() {
        let got = reducer.verdict(&header(1, entry.number, 1), Abi::X86_64);
        let want = if old.contains(&entry.number) {
            Verdict::Keep
        } else {
            Verdict::Drop(Some(entry.name.as_str()))
        };
        assert_eq!(got, want, "{}", entry.name);
    }
    // Other records of an x86-64 guest (x32, an older guest's ia32: ABI 0 and
    // 2) and non-entry phases are kept, as they were.
    for abi in [0, 2] {
        let read = table(Abi::X86_64).number("read").unwrap();
        assert_eq!(
            reducer.verdict(&header(abi, read, 1), Abi::X86_64),
            Verdict::Keep
        );
    }
    let read = table(Abi::X86_64).number("read").unwrap();
    assert_eq!(
        reducer.verdict(&header(1, read, 3), Abi::X86_64),
        Verdict::Keep
    );
}

#[test]
fn aarch64_calls_are_kept_and_dropped_by_their_names() {
    for name in ["execve", "openat"] {
        assert_eq!(
            verdict(Abi::Aarch64, 1, Abi::Aarch64, name),
            Verdict::Keep,
            "{name}"
        );
    }
    // x86-64's execve number is another call on aarch64: the x86-64 list
    // must not decide an arm64 call.
    assert_eq!(
        verdict(Abi::Aarch64, 1, Abi::Aarch64, "read"),
        Verdict::Drop(Some("read"))
    );
    let x86_execve = table(Abi::X86_64).number("execve").unwrap();
    let reducer = Reducer::new(&list());
    let on_arm = table(Abi::Aarch64)
        .by_number(x86_execve)
        .map(|e| e.name.as_str());
    if let Some(name) = on_arm.filter(|name| !list().iter().any(|l| l == name)) {
        assert_eq!(
            reducer.verdict(&header(1, x86_execve, 1), Abi::Aarch64),
            Verdict::Drop(Some(name))
        );
    }
}

#[test]
fn aarch32_calls_use_the_arm_table() {
    for name in ["execve", "openat", "mmap2"] {
        assert_eq!(
            verdict(Abi::Aarch64, 3, Abi::Arm, name),
            Verdict::Keep,
            "{name}"
        );
    }
    assert_eq!(
        verdict(Abi::Aarch64, 3, Abi::Arm, "read"),
        Verdict::Drop(Some("read"))
    );
    // The same number native is another call.
    let arm_execve = table(Abi::Arm).number("execve").unwrap();
    let native = table(Abi::Aarch64)
        .by_number(arm_execve)
        .map(|e| e.name.as_str());
    let reducer = Reducer::new(&list());
    if let Some(native) = native.filter(|name| !list().iter().any(|l| l == name)) {
        assert_eq!(
            reducer.verdict(&header(1, arm_execve, 1), Abi::Aarch64),
            Verdict::Drop(Some(native))
        );
    }
}

#[test]
fn ia32_calls_use_the_i386_table() {
    for name in ["execve", "open", "mmap2"] {
        let kept = verdict(Abi::X86_64, 3, Abi::I386, name);
        // `open` is not on the list under that name; `openat` is.
        let expect = if name == "open" {
            Verdict::Drop(Some("open"))
        } else {
            Verdict::Keep
        };
        assert_eq!(kept, expect, "{name}");
    }
    assert_eq!(
        verdict(Abi::X86_64, 3, Abi::I386, "read"),
        Verdict::Drop(Some("read"))
    );
    // i386's execve number is another call on x86-64; the old code kept every
    // ABI 3 call, and an ia32 execve must still be kept.
    let reducer = Reducer::new(&list());
    let execve = table(Abi::I386).number("execve").unwrap();
    assert_eq!(
        reducer.verdict(&header(3, execve, 1), Abi::X86_64),
        Verdict::Keep
    );
}

#[test]
fn unknown_numbers_and_lifecycle_are_kept_on_every_abi() {
    let reducer = Reducer::new(&list());
    for (native, abi) in [
        (Abi::Aarch64, 1),
        (Abi::Aarch64, 3),
        (Abi::X86_64, 1),
        (Abi::X86_64, 3),
    ] {
        assert_eq!(
            reducer.verdict(&header(abi, 99_999, 1), native),
            Verdict::Keep
        );
        let mut lifecycle = header(abi, 0, 3);
        lifecycle.record_type = 1;
        assert_eq!(reducer.verdict(&lifecycle, native), Verdict::Keep);
    }
    // Another ABI's call on an arm64 guest is held, never dropped.
    assert_eq!(
        reducer.verdict(&header(2, 5, 1), Abi::Aarch64),
        Verdict::Keep
    );
}

#[test]
fn only_the_entry_names_a_dropped_call() {
    let reducer = Reducer::new(&list());
    let read = table(Abi::Aarch64).number("read").unwrap();
    assert_eq!(
        reducer.verdict(&header(1, read, 2), Abi::Aarch64),
        Verdict::Drop(None)
    );
}
