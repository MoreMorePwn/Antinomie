// SPDX-License-Identifier: GPL-3.0-only
//! The process table: threads, forked children, arguments and renames.
use super::rules::tests::support::{exec, fork, sys, with_entry};
use super::tests::{call, captured, path_call};
use super::*;

const CLONE_NR: u64 = 56;
const CLONE3_NR: u64 = 435;

/// The call as made by a task of `pid` with its own `tid` and `cookie`.
fn as_task(mut row: InvocationSummary, pid: u32, tid: u32, cookie: u64) -> InvocationSummary {
    row.task_cookie = cookie;
    for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
        event.pid = pid;
        event.tid = tid;
        event.task_cookie = cookie;
    }
    row
}

fn node(nodes: &[ProcessNode], pid: u32, cookie: u64) -> &ProcessNode {
    nodes
        .iter()
        .find(|node| node.pid == pid && node.cookie == cookie)
        .unwrap_or_else(|| panic!("no node {pid}/{cookie}"))
}

#[test]
fn runtime_threads_sit_under_their_process_and_take_its_image() {
    let mut main = exec(7, "/tmp/kaiji", &["kaiji", "-x"]);
    main = as_task(main, 7, 7, 70);
    let mut calls = vec![main];
    for tid in 8u32..12 {
        calls.push(as_task(
            call(7, 202, "futex", 0),
            7,
            tid,
            70 + u64::from(tid),
        ));
    }
    let nodes = process_nodes(&calls);
    assert_eq!(nodes.len(), 5);
    assert!(nodes
        .iter()
        .all(|node| !node.parent_missing || node.pid == 7));
    for tid in 8u32..12 {
        let thread = node(&nodes, 7, 70 + u64::from(tid));
        assert!(thread.thread);
        assert_eq!(thread.parent.unwrap().cookie, 70);
        assert_eq!(thread.depth, 1);
        assert_eq!(thread.comm, "/tmp/kaiji");
        assert_eq!(thread.argv, ["kaiji", "-x"]);
        assert!(!thread.parent_missing);
        assert!(process_label(thread).contains("thread"));
    }
    assert!(!node(&nodes, 7, 70).thread);
}

#[test]
fn two_pids_with_matching_tids_are_not_threads() {
    let calls = vec![
        as_task(call(7, 1, "write", 0), 7, 7, 100),
        as_task(call(7, 1, "write", 0), 7, 7, 200),
    ];
    let nodes = process_nodes(&calls);
    assert!(nodes.iter().all(|node| !node.thread));
}

#[test]
fn a_forked_child_with_its_own_threads_is_still_linked_to_its_parent() {
    // The child's threads were recorded before the parent's fork returned.
    let calls = vec![
        as_task(call(42, 1, "write", 0), 42, 42, 420),
        as_task(call(42, 1, "write", 0), 42, 43, 430),
        as_task(call(42, 1, "write", 0), 42, 44, 440),
        as_task(fork(1, 42), 1, 1, 10),
    ];
    let nodes = process_nodes(&calls);
    let child = node(&nodes, 42, 420);
    assert_eq!(child.parent.unwrap().pid, 1);
    assert!(!child.parent_missing);
    assert!(node(&nodes, 42, 430).thread);
    assert_eq!(node(&nodes, 42, 430).parent.unwrap().cookie, 420);
}

#[test]
fn a_forked_child_without_exec_keeps_its_parents_image() {
    let calls = vec![
        as_task(exec(1, "/tmp/mirai", &["mirai", "a"]), 1, 1, 10),
        as_task(fork(1, 5), 1, 1, 10),
        as_task(call(5, 1, "write", 0), 5, 5, 50),
    ];
    let nodes = process_nodes(&calls);
    let child = node(&nodes, 5, 50);
    assert_eq!(child.parent.unwrap().pid, 1);
    assert_eq!(child.comm, "/tmp/mirai");
    assert_eq!(child.argv, ["mirai", "a"]);
}

#[test]
fn the_guests_child_record_links_a_clone3_whose_flags_were_not_captured() {
    let mut spawn = as_task(
        sys(1, CLONE3_NR, "clone3", [0, 88, 0, 0, 0, 0], 9),
        1,
        1,
        10,
    );
    spawn.async_events.push({
        let mut note = spawn.exit.clone().unwrap();
        note.phase = 3;
        note.fields = vec![captured("lifecycle.child_tgid", "u64", &9u64.to_le_bytes())];
        note
    });
    let calls = vec![
        as_task(exec(1, "/bin/root", &["root"]), 1, 1, 10),
        spawn,
        as_task(exec(9, "/bin/sh", &["sh", "-c", "id"]), 9, 9, 90),
    ];
    let nodes = process_nodes(&calls);
    let sh = node(&nodes, 9, 90);
    assert_eq!(sh.parent.unwrap().pid, 1);
    assert!(!sh.parent_missing);
    // A clone with the thread flag and no child record stays a thread.
    let thread = sys(
        1,
        CLONE_NR,
        "clone",
        [super::CLONE_THREAD, 0, 0, 0, 0, 0],
        77,
    );
    assert!(process_nodes(&[thread]).iter().all(|node| node.pid != 77));
}

#[test]
fn the_table_shows_the_arguments_the_exec_was_given() {
    let nodes = process_nodes(&[exec(3, "/bin/sh", &["sh", "-c", "echo hi"])]);
    assert_eq!(nodes[0].argv, ["sh", "-c", "echo hi"]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0][3].text, "sh -c echo hi");
}

fn prctl_name(pid: u32, name: &str) -> InvocationSummary {
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    with_entry(
        sys(pid, 157, "prctl", [15, 0x2000, 0, 0, 0, 0], 0),
        "arg1.name",
        &bytes,
    )
}

#[test]
fn a_rename_is_shown_for_any_process_not_only_a_daemon_look_alike() {
    let nodes = process_nodes(&[exec(3, "/tmp/x", &["x"]), prctl_name(3, "httpd")]);
    assert_eq!(nodes[0].renames, ["httpd"]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert!(
        rows[0][7].text.contains("renamed to \"httpd\""),
        "{}",
        rows[0][7].text
    );
    // A new exec starts the names over.
    let nodes = process_nodes(&[prctl_name(3, "httpd"), exec(3, "/tmp/y", &["y"])]);
    assert!(nodes[0].renames.is_empty());
}

#[test]
fn a_write_to_the_comm_file_is_a_rename() {
    let open = path_call(3, 257, "openat", 5, "/proc/self/comm");
    let write = with_entry(
        sys(3, 1, "write", [5, 0x3000, 5, 0, 0, 0], 5),
        "arg1.buf",
        b"kdmtmpflush",
    );
    let other = with_entry(
        sys(3, 1, "write", [6, 0x3000, 5, 0, 0, 0], 5),
        "arg1.buf",
        b"nope",
    );
    let nodes = process_nodes(&[open, other, write]);
    assert_eq!(nodes[0].renames, ["kdmtmpflush"]);
}

fn entry_only(mut row: InvocationSummary, at: u64) -> InvocationSummary {
    row.exit = None;
    row.entry.as_mut().unwrap().timestamp_ns = at;
    row
}

#[test]
fn a_call_still_blocking_at_the_stop_is_shown_with_where_it_started() {
    let blocked = entry_only(
        sys(3, 0, "read", [0, 0x1000, 33, 0, 0, 0], 0),
        2_000_000_000,
    );
    let mut later = call(4, 1, "write", 0);
    later.entry.as_mut().unwrap().timestamp_ns = 292_000_000_000;
    let nodes = process_nodes(&[blocked, later]);
    let blocked = node(&nodes, 3, 3);
    assert_eq!(blocked.in_call.as_ref().unwrap().0, "read");
    let rows = process_rows(&nodes, None, &Suspicious::new());
    let state = &rows.iter().find(|row| row[2].text == "3").unwrap()[6].text;
    assert!(
        state.contains("still in progress at the stop: read since"),
        "{state}"
    );
    assert!(state.contains("290.0 s before the last record"), "{state}");
    // The task made another call afterwards: it was not blocked.
    let moved_on = process_nodes(&[
        entry_only(sys(3, 0, "read", [0; 6], 0), 1),
        call(3, 1, "write", 0),
    ]);
    assert!(moved_on[0].in_call.is_none());
    // exit_group never returns: it is not a call in progress.
    let leaving = process_nodes(&[entry_only(sys(3, 231, "exit_group", [0; 6], 0), 1)]);
    assert!(leaving[0].in_call.is_none());
}
