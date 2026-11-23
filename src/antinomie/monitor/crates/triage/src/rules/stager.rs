// SPDX-License-Identifier: GPL-3.0-only
//! An in-memory stager (ANT-T0604): one process receives bytes from a
//! connected stream socket into memory that is executable, or that it then
//! makes executable. Metasploit's Linux stagers (and the Mettle payloads they
//! load) map memory read-write-execute, read the next stage from the socket
//! into it and jump to it; others read into writable memory and mprotect it
//! executable afterwards. No file is written, so no file rule sees it.
use super::ctx::Ctx;
use super::process::PROT_EXEC;
use super::state::State;
use super::Hit;
use crate::sigma_events::Socket;

/// Ranges remembered per process, so a long run's mappings stay bounded.
const MAX_RANGES: usize = 4096;
/// Received buffers remembered per process while they wait for an mprotect.
const MAX_RECEIVED: usize = 256;

fn overlaps(ranges: &[(u64, u64)], start: u64, length: u64) -> bool {
    let end = start.saturating_add(length.max(1));
    ranges
        .iter()
        .any(|(from, size)| *from < end && start < from.saturating_add(*size))
}

/// mmap or mprotect: remember executable anonymous memory, and report a
/// received buffer that is made executable now.
pub fn memory(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let prot = cx.args[2];
    if !cx.ok || prot & PROT_EXEC == 0 {
        return;
    }
    let anonymous = cx.name != "mmap" || cx.args[3] & 0x20 != 0;
    if !anonymous {
        return;
    }
    let (start, length) = if cx.name == "mmap" {
        (cx.ret.unwrap_or(0) as u64, cx.args[1])
    } else {
        (cx.args[0], cx.args[1])
    };
    let task = st.task(cx);
    if task.exec_ranges.len() < MAX_RANGES {
        task.exec_ranges.push((start, length));
    }
    if cx.name == "mmap" || task.stager_done {
        return;
    }
    let received = task
        .received_into
        .iter()
        .find(|(at, size, _)| overlaps(&[(start, length)], *at, *size))
        .cloned();
    if let Some((at, size, endpoint)) = received {
        task.stager_done = true;
        out.push(stager_hit(
            &endpoint,
            format!(
                "{} makes executable the memory at {at:#x} that received {size} bytes from {endpoint}",
                cx.name
            ),
        ));
    }
}

/// A read or recvfrom on a connected stream socket: report a buffer in
/// executable memory, remember one in writable memory.
pub fn receive(cx: &Ctx, st: &mut State, socket: &Socket, out: &mut Vec<Hit>) {
    if !matches!(cx.name, "read" | "recvfrom") || socket.is_datagram() || socket.raw {
        return;
    }
    let Some((ip, port)) = socket.peer else {
        return;
    };
    let Some(size) = cx.ret.filter(|ret| *ret > 0).map(|ret| ret as u64) else {
        return;
    };
    let at = cx.args[1];
    let endpoint = format!("{ip}:{port}");
    let task = st.task(cx);
    if task.stager_done {
        return;
    }
    if overlaps(&task.exec_ranges, at, size) {
        task.stager_done = true;
        out.push(stager_hit(
            &endpoint,
            format!(
                "{} puts {size} bytes from {endpoint} into executable memory at {at:#x}",
                cx.name
            ),
        ));
    } else if overlaps(&task.writable, at, size) && task.received_into.len() < MAX_RECEIVED {
        task.received_into.push((at, size, endpoint));
    }
}

fn stager_hit(endpoint: &str, summary: String) -> Hit {
    Hit::new("execution.socket_stager", endpoint, summary).detail(
        "Code received over the network is about to run from memory: the process read from a connected socket into memory it can execute. Metasploit's stagers load Meterpreter and Mettle this way; no file is written.",
    )
}
