// SPDX-License-Identifier: GPL-3.0-only
//! Names of sockets, pipes and anonymous inodes (ANT-T0593).
use super::descriptor_names::{self, Kind};
use super::file_category::{self, Access, Category};
use super::sigma_events_tests::{of, run, with_address, with_args, with_path};
use super::*;

const WRITE: u64 = 1;
const READ: u64 = 0;
const SOCKET: u64 = 41;
const CONNECT: u64 = 42;
const ACCEPT: u64 = 43;
const BIND: u64 = 49;
const PIPE2: u64 = 293;
const EVENTFD2: u64 = 290;
const MEMFD: u64 = 319;
const DUP: u64 = 32;
const CLOSE: u64 = 3;

fn io(nr: u64, name: &str, fd: u64, size: i64) -> InvocationSummary {
    with_args(
        tests::call(1, nr, name, size),
        [fd, 0, size.max(0) as u64, 0, 0, 0],
    )
}

fn fds(mut call: InvocationSummary, key: &str, pair: [i32; 2]) -> InvocationSummary {
    let mut data = pair[0].to_le_bytes().to_vec();
    data.extend(pair[1].to_le_bytes());
    call.exit
        .as_mut()
        .unwrap()
        .fields
        .push(tests::captured(key, "", &data));
    call
}

/// Remember each call as the scan does, and name the file of the last one.
fn shown(calls: &[InvocationSummary]) -> (FdState, String, Vec<Category>) {
    let mut files = FdState::default();
    let (last, before) = calls.split_last().unwrap();
    for call in before {
        let event = trace::representative(call).unwrap().clone();
        remember_open(&mut files, call, &event);
        forget_closed(&mut files, call, &event);
        apply_dup(&mut files, call, &event);
    }
    let event = trace::representative(last).unwrap().clone();
    let row = file_events::event_row(&files, last, &event);
    let categories = file_category::classify(&files, last, &event)
        .into_iter()
        .map(|hit| hit.category)
        .collect();
    (files, row[0].text.clone(), categories)
}

fn connected(fd: i64) -> Vec<InvocationSummary> {
    vec![
        with_args(tests::call(1, SOCKET, "socket", fd), [2, 1, 0, 0, 0, 0]),
        with_address(
            with_args(tests::call(1, CONNECT, "connect", 0), [fd as u64, 0, 16, 0, 0, 0]),
            "arg1.uservaddr",
            2,
            [189, 53, 235, 111],
            8080,
        ),
    ]
}

#[test]
pub fn a_connected_socket_is_named_by_its_peer() {
    let mut calls = connected(4);
    calls.push(io(WRITE, "write", 4, 324));
    let (files, path, categories) = shown(&calls);
    assert_eq!(path, "socket → 189.53.235.111:8080 (tcp)");
    // The socket's traffic is network I/O, not a file write.
    assert_eq!(categories, [Category::Socket]);
    let write = calls.last().unwrap();
    let event = trace::representative(write).unwrap();
    assert_eq!(file_category::access(&files, write, event), Access::ByDescriptor);
    let row = file_category::category_row(
        &files,
        write,
        event,
        file_category::Hit {
            category: Category::Socket,
            inferred: false,
        },
    );
    assert_eq!(row[3].text, "socket → 189.53.235.111:8080 (tcp)");
    assert_eq!(row[4].text, "324 bytes sent");
    assert!(row[0]
        .values
        .iter()
        .any(|(key, value)| *key == "file.descriptor"
            && matches!(value, RowValue::Text(kind) if kind == "socket")));
}

#[test]
pub fn a_bound_and_an_accepted_socket_are_named_by_where_they_listen_and_who_came() {
    let listener = |extra: Vec<InvocationSummary>| {
        let mut calls = vec![
            with_args(tests::call(1, SOCKET, "socket", 3), [2, 1, 0, 0, 0, 0]),
            with_address(
                with_args(tests::call(1, BIND, "bind", 0), [3, 0, 16, 0, 0, 0]),
                "arg1.umyaddr",
                2,
                [10, 0, 2, 15],
                23,
            ),
        ];
        calls.extend(extra);
        calls
    };
    let (_, path, _) = shown(&listener(vec![io(READ, "read", 3, 0)]));
    assert_eq!(path, "socket ← 10.0.2.15:23 (tcp)");
    let accept = with_address(
        with_args(tests::call(1, ACCEPT, "accept", 5), [3, 0, 0, 0, 0, 0]),
        "arg1.upeer_sockaddr",
        2,
        [198, 51, 100, 7],
        40000,
    );
    let (_, path, categories) = shown(&listener(vec![accept, io(READ, "read", 5, 12)]));
    assert_eq!(path, "socket ← 198.51.100.7:40000 (tcp)");
    assert_eq!(categories, [Category::Socket]);
    // An accept that captured no peer falls back to the listener's address.
    let anonymous = with_args(tests::call(1, ACCEPT, "accept", 5), [3, 0, 0, 0, 0, 0]);
    let (_, path, _) = shown(&listener(vec![anonymous, io(READ, "read", 5, 12)]));
    assert_eq!(path, "socket ← 10.0.2.15:23 (tcp)");
}

#[test]
pub fn udp_unix_and_netlink_sockets_say_what_they_are() {
    let socket = |domain: u64, kind: u64| {
        with_args(tests::call(1, SOCKET, "socket", 7), [domain, kind, 0, 0, 0, 0])
    };
    for (domain, kind, label) in [
        (2, 2, "socket (udp)"),
        (1, 1, "socket (unix)"),
        (16, 3, "socket (netlink)"),
        (17, 3, "socket (packet)"),
        (2, 3, "socket (raw)"),
    ] {
        let (_, path, _) = shown(&[socket(domain, kind), io(WRITE, "write", 7, 1)]);
        assert_eq!(path, label);
    }
    let mut address = 1u16.to_le_bytes().to_vec();
    address.extend(b"/tmp/.X11-unix/X0\0");
    let mut connect = with_args(tests::call(1, CONNECT, "connect", 0), [7, 0, 20, 0, 0, 0]);
    connect
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(tests::captured("arg1.uservaddr", "", &address));
    let (_, path, _) = shown(&[socket(1, 1), connect, io(READ, "read", 7, 4)]);
    assert_eq!(path, "socket → /tmp/.X11-unix/X0 (unix)");
}

#[test]
pub fn pipes_eventfds_and_memfds_are_named_and_stay_in_the_written_tab() {
    let pipe = fds(
        with_args(tests::call(1, PIPE2, "pipe2", 0), [0, 0x80000, 0, 0, 0, 0]),
        "arg0.fildes",
        [5, 6],
    );
    let (files, path, categories) = shown(&[pipe.clone(), io(WRITE, "write", 6, 3)]);
    assert_eq!(path, "pipe (write end)");
    assert_eq!(categories, [Category::Written]);
    let read_end = files.opened.iter().find(|(key, _)| key.2 == 5);
    assert_eq!(read_end.map(|(_, label)| label.as_str()), Some("pipe (read end)"));
    // O_CLOEXEC on the pipe is remembered for exec.
    assert!(files.cloexec.iter().any(|key| key.2 == 5));
    let (_, path, _) = shown(&[pipe, io(READ, "read", 5, 3)]);
    assert_eq!(path, "pipe (read end)");
    let event = with_args(tests::call(1, EVENTFD2, "eventfd2", 8), [0, 0, 0, 0, 0, 0]);
    let (_, path, _) = shown(&[event, io(WRITE, "write", 8, 8)]);
    assert_eq!(path, "eventfd");
    let memfd = with_path(tests::call(1, MEMFD, "memfd_create", 9), "arg0.uname", "payload");
    let (_, path, categories) = shown(&[memfd, io(WRITE, "write", 9, 100)]);
    assert_eq!(path, "memfd:payload");
    assert_eq!(categories, [Category::Written]);
}

#[test]
pub fn a_duplicate_keeps_the_name_and_a_close_drops_it() {
    let mut calls = connected(4);
    calls.push(with_args(tests::call(1, DUP, "dup", 9), [4, 0, 0, 0, 0, 0]));
    calls.push(io(WRITE, "write", 9, 5));
    let (_, path, _) = shown(&calls);
    assert_eq!(path, "socket → 189.53.235.111:8080 (tcp)");
    let mut calls = connected(4);
    calls.push(with_args(tests::call(1, CLOSE, "close", 0), [4, 0, 0, 0, 0, 0]));
    calls.push(io(WRITE, "write", 4, 5));
    let (_, path, _) = shown(&calls);
    assert_eq!(path, "—");
}

#[test]
pub fn a_descriptor_from_before_the_recording_stays_unnamed_and_says_so() {
    let write = io(WRITE, "write", 4, 5);
    let files = FdState::default();
    let event = trace::representative(&write).unwrap();
    let row = file_events::event_row(&files, &write, event);
    assert_eq!(row[0].text, "—");
    assert_eq!(
        row[0].note.as_deref(),
        Some("descriptor opened before the recording")
    );
    assert_eq!(
        file_category::access(&files, &write, event),
        Access::Inherited
    );
}

#[test]
pub fn the_journal_names_the_descriptor_and_leaves_target_filename_empty() {
    let mut calls = connected(4);
    calls.push(io(WRITE, "write", 4, 324));
    let fd = with_args(tests::call(1, EVENTFD2, "eventfd2", 8), [0, 0, 0, 0, 0, 0]);
    calls.push(fd);
    calls.push(io(WRITE, "write", 8, 8));
    let mut files = FdState::default();
    let events = run(&mut files, &calls);
    let access = of(&events, "file_access");
    assert_eq!(access.len(), 2, "{access:?}");
    assert_eq!(
        access[0]["fields"]["Descriptor"],
        "socket → 189.53.235.111:8080 (tcp)"
    );
    assert!(access[0]["fields"].get("TargetFilename").is_none());
    assert_eq!(access[1]["fields"]["Descriptor"], "eventfd");
    assert_eq!(access[0]["fields"]["TransferredSize"], 324);
}

#[test]
pub fn names_are_told_from_paths_by_kind() {
    assert_eq!(
        descriptor_names::kind("socket ← 10.0.2.15:23 (tcp)"),
        Some(Kind::Socket)
    );
    assert_eq!(descriptor_names::kind("/tmp/socket (tcp)"), None);
}
